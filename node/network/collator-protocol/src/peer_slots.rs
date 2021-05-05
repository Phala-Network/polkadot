use super::{CollatorId, CollatorProtocolMessage, PeerId, SubsystemContext, LOG_TARGET};
use std::time::Instant;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::ops::{Index, IndexMut};

use rand::{thread_rng, Rng, rngs::ThreadRng};
use rand::prelude::SliceRandom;

use sp_keystore::SyncCryptoStorePtr;

use polkadot_node_network_protocol::{UnifiedReputationChange as Rep, View};
use polkadot_primitives::v1::{Hash, Id as ParaId};
use polkadot_subsystem::{messages::{AllMessages, NetworkBridgeMessage}, SubsystemSender};

pub(crate) const CACHE_SIZE: usize = 10_000;
pub(crate) const RESERVOIR_SIZE: usize = 1_000;

pub(crate) const COST_UNEXPECTED_MESSAGE: Rep = Rep::CostMinor("An unexpected message");
/// Message could not be decoded properly.
pub(crate) const COST_CORRUPTED_MESSAGE: Rep = Rep::CostMinor("Message was corrupt");
/// Network errors that originated at the remote host should have same cost as timeout.
pub(crate) const COST_NETWORK_ERROR: Rep = Rep::CostMinor("Some network error");
pub(crate) const COST_REQUEST_TIMED_OUT: Rep =
	Rep::CostMinor("A collation request has timed out");
pub(crate) const COST_INVALID_SIGNATURE: Rep =
	Rep::Malicious("Invalid network message signature");
pub(crate) const COST_WRONG_PARA: Rep =
	Rep::Malicious("A collator provided a collation for the wrong para");
pub(crate) const COST_UNNEEDED_COLLATOR: Rep = Rep::CostMinor("An unneeded collator connected");

pub(crate) const COST_REPORT_BAD: Rep =
	Rep::Malicious("A collator was reported by another subsystem");
pub(crate) const BENEFIT_NOTIFY_GOOD: Rep =
	Rep::BenefitMinor("A collator was noted good by another subsystem");

const COLLATOR_METRICS: [Rep; 9] = [
	COST_UNEXPECTED_MESSAGE,
	COST_CORRUPTED_MESSAGE,
	COST_NETWORK_ERROR,
	COST_REQUEST_TIMED_OUT,
	COST_INVALID_SIGNATURE,
	COST_WRONG_PARA,
	COST_UNNEEDED_COLLATOR,
	COST_REPORT_BAD,
	BENEFIT_NOTIFY_GOOD,
];

#[derive(Copy, Clone)]
#[repr(usize)]
pub enum FitnessEvent {
	Unexpected = 0,
	Corrupted = 1,
	NetworkError = 2,
	Timeout = 3,
	SigError = 4,
	ParaError = 5,
	Superfluous = 6,
	ReportBad = 7,
	NotifyGood = 8,
}

#[derive(Copy, Clone)]
pub struct FitnessMetric {
	last: std::time::Instant,
	avg: f64,
	total: u64,
}

impl PartialEq for FitnessMetric {
	fn eq(&self, other: &Self) -> bool {
		(self.avg - other.avg).abs() < f64::EPSILON
	}
}

impl Eq for FitnessMetric {}

impl PartialOrd for FitnessMetric {
	fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
		Some(self.cmp(other))
	}
}

impl Ord for FitnessMetric {
	fn cmp(&self, other: &Self) -> std::cmp::Ordering {
		if self.avg < other.avg {
			std::cmp::Ordering::Less
		} else {
			std::cmp::Ordering::Greater
		}
	}
}

impl FitnessMetric {
	pub fn new() -> Self {
		Self {
			last: std::time::Instant::now(),
			avg: 0f64,
			total: 0u64,
		}
	}

	pub fn insert_event(&mut self) {
		let mut cumulative = if self.avg == 0f64 {
			0f64
		} else {
			self.total as f64 / self.avg
		};
		self.total += 1;
		cumulative += self.last.elapsed().as_secs() as f64;
		self.avg = self.total as f64 / cumulative;
		self.last = std::time::Instant::now();
	}
}

pub struct CollatorFitnessMetric([FitnessMetric; 9]);

impl Index<FitnessEvent> for CollatorFitnessMetric {
    type Output = FitnessMetric;
	fn index(&self, index: FitnessEvent) -> &FitnessMetric {
        &self.0[index as usize]
	}
}

impl IndexMut<FitnessEvent> for CollatorFitnessMetric {
	fn index_mut(&mut self, index: FitnessEvent) -> &mut FitnessMetric {
		&mut self.0[index as usize]
	}
}

impl CollatorFitnessMetric {
	pub fn insert_event(&mut self, event: FitnessEvent) {
		(&mut self[event]).insert_event()
	}

	// Compute collator's fitness value.
	// Note that this is a naive sum of all metric averages.
	// In the future we will expand on this functionality.
	pub fn compute_fitness(&self) -> f64 {
		self.0.iter().map(|a| a.avg).sum::<f64>()
	}
}

impl Default for CollatorFitnessMetric {
	fn default() -> Self {
		Self([FitnessMetric::new(); COLLATOR_METRICS.len()])
	}
}

#[derive(Debug)]
pub enum AdvertisementError {
	Duplicate,
	OutOfOurView,
	UndeclaredCollator,
}

struct CollatingPeerState {
	collator_id: CollatorId,
	para_id: ParaId,
	// Advertised relay parents.
	advertisements: HashSet<Hash>,
	last_active: Instant,
}

enum PeerState {
	// The peer has connected at the given instant.
	Connected(Instant),
	// Thepe
	Collating(CollatingPeerState),
}

pub(crate) struct PeerData {
	view: View,
	state: PeerState,
}

impl PeerData {
	pub fn new(view: View) -> Self {
		PeerData {
			view,
			state: PeerState::Connected(Instant::now()),
		}
	}

	/// Update the view, clearing all advertisements that are no longer in the
	/// current view.
	pub fn update_view(&mut self, new_view: View) {
		let old_view = std::mem::replace(&mut self.view, new_view);
		if let PeerState::Collating(ref mut peer_state) = self.state {
			for removed in old_view.difference(&self.view) {
				let _ = peer_state.advertisements.remove(&removed);
			}
		}
	}

	/// Prune old advertisements relative to our view.
	pub fn prune_old_advertisements(&mut self, our_view: &View) {
		if let PeerState::Collating(ref mut peer_state) = self.state {
			peer_state.advertisements.retain(|a| our_view.contains(a));
		}
	}

	/// Note an advertisement by the collator. Returns `true` if the advertisement was imported
	/// successfully. Fails if the advertisement is duplicate, out of view, or the peer has not
	/// declared itself a collator.
	pub fn insert_advertisement(
		&mut self,
		on_relay_parent: Hash,
		our_view: &View,
	)
		-> std::result::Result<(CollatorId, ParaId), AdvertisementError>
	{
		match self.state {
			PeerState::Connected(_) => Err(AdvertisementError::UndeclaredCollator),
			_ if !our_view.contains(&on_relay_parent) => Err(AdvertisementError::OutOfOurView),
			PeerState::Collating(ref mut state) => {
				if state.advertisements.insert(on_relay_parent) {
					state.last_active = Instant::now();
					Ok((state.collator_id.clone(), state.para_id.clone()))
				} else {
					Err(AdvertisementError::Duplicate)
				}
			}
		}
	}

	/// Whether a peer is collating.
	pub fn is_collating(&self) -> bool {
		match self.state {
			PeerState::Connected(_) => false,
			PeerState::Collating(_) => true,
		}
	}

	/// Note that a peer is now collating with the given collator and para ids.
	///
	/// This will overwrite any previous call to `set_collating` and should only be called
	/// if `is_collating` is false.
	pub fn set_collating(&mut self, collator_id: &CollatorId, para_id: &ParaId) {
		self.state = PeerState::Collating(CollatingPeerState {
			collator_id: collator_id.clone(),
			para_id: *para_id,
			advertisements: HashSet::new(),
			last_active: Instant::now(),
		});
	}

	pub fn collator_id(&self) -> Option<&CollatorId> {
		match self.state {
			PeerState::Connected(_) => None,
			PeerState::Collating(ref state) => Some(&state.collator_id),
		}
	}

	pub fn collating_para(&self) -> Option<ParaId> {
		match self.state {
			PeerState::Connected(_) => None,
			PeerState::Collating(ref state) => Some(state.para_id),
		}
	}

	/// Whether the peer has advertised the given collation.
	pub fn has_advertised(&self, relay_parent: &Hash) -> bool {
		match self.state {
			PeerState::Connected(_) => false,
			PeerState::Collating(ref state) => state.advertisements.contains(relay_parent),
		}
	}

	/// Whether the peer is now inactive according to the current instant and the eviction policy.
	pub fn is_inactive(&self, now: Instant, policy: &crate::CollatorEvictionPolicy) -> bool {
		match self.state {
			PeerState::Connected(connected_at) => connected_at + policy.undeclared < now,
			PeerState::Collating(ref state) => state.last_active + policy.inactive_collator < now,
		}
	}
}

impl Default for PeerData {
	fn default() -> Self {
		PeerData::new(Default::default())
	}
}

struct GroupAssignments {
	current: Option<ParaId>,
	next: Option<ParaId>,
}

#[derive(Default)]
pub(crate) struct ActiveParas {
	relay_parent_assignments: HashMap<Hash, GroupAssignments>,
	current_assignments: HashMap<ParaId, usize>,
	next_assignments: HashMap<ParaId, usize>
}

impl ActiveParas {
	pub(crate) async fn assign_incoming(
		&mut self,
		sender: &mut impl SubsystemSender,
		keystore: &SyncCryptoStorePtr,
		new_relay_parents: impl IntoIterator<Item = Hash>,
	) {
		for relay_parent in new_relay_parents {
			let mv = polkadot_node_subsystem_util::request_validators(relay_parent, sender)
				.await
				.await
				.ok()
				.map(|x| x.ok())
				.flatten();

			let mg = polkadot_node_subsystem_util::request_validator_groups(relay_parent, sender)
				.await
				.await
				.ok()
				.map(|x| x.ok())
				.flatten();


			let mc = polkadot_node_subsystem_util::request_availability_cores(relay_parent, sender)
				.await
				.await
				.ok()
				.map(|x| x.ok())
				.flatten();

			let (validators, groups, rotation_info, cores) = match (mv, mg, mc) {
				(Some(v), Some((g, r)), Some(c)) => (v, g, r, c),
				_ => {
					tracing::debug!(
						target: LOG_TARGET,
						relay_parent = ?relay_parent,
						"Failed to query runtime API for relay-parent",
					);

					continue
				}
			};

			let (para_now, para_next) = match polkadot_node_subsystem_util
				::signing_key_and_index(&validators, keystore)
				.await
				.and_then(|(_, index)| polkadot_node_subsystem_util::find_validator_group(
					&groups,
					index,
				))
			{
				Some(group) => {
					let next_rotation_info = rotation_info.bump_rotation();

					let core_now = rotation_info.core_for_group(group, cores.len());
					let core_next = next_rotation_info.core_for_group(group, cores.len());

					(
						cores.get(core_now.0 as usize).and_then(|c| c.para_id()),
						cores.get(core_next.0 as usize).and_then(|c| c.para_id()),
					)
				}
				None => {
					tracing::trace!(
						target: LOG_TARGET,
						relay_parent = ?relay_parent,
						"Not a validator",
					);

					continue
				}
			};

			// This code won't work well, if at all for parathreads. For parathreads we'll
			// have to be aware of which core the parathread claim is going to be multiplexed
			// onto. The parathread claim will also have a known collator, and we should always
			// allow an incoming connection from that collator. If not even connecting to them
			// directly.
			//
			// However, this'll work fine for parachains, as each parachain gets a dedicated
			// core.
			if let Some(para_now) = para_now {
				*self.current_assignments.entry(para_now).or_default() += 1;
			}

			if let Some(para_next) = para_next {
				*self.next_assignments.entry(para_next).or_default() += 1;
			}

			self.relay_parent_assignments.insert(
				relay_parent,
				GroupAssignments { current: para_now, next: para_next },
			);
		}
	}

	pub(crate) fn remove_outgoing(
		&mut self,
		old_relay_parents: impl IntoIterator<Item = Hash>,
	) {
		for old_relay_parent in old_relay_parents {
			if let Some(assignments) = self.relay_parent_assignments.remove(&old_relay_parent) {
				let GroupAssignments { current, next } = assignments;

				if let Some(cur) = current {
					if let Entry::Occupied(mut occupied) = self.current_assignments.entry(cur) {
						*occupied.get_mut() -= 1;
						if *occupied.get() == 0 {
							occupied.remove_entry();
						}
					}
				}

				if let Some(next) = next {
					if let Entry::Occupied(mut occupied) = self.next_assignments.entry(next) {
						*occupied.get_mut() -= 1;
						if *occupied.get() == 0 {
							occupied.remove_entry();
						}
					}
				}
			}
		}
	}

	pub(crate) fn is_current_or_next(&self, id: ParaId) -> bool {
		self.current_assignments.contains_key(&id) || self.next_assignments.contains_key(&id)
	}
}

pub(crate) type CollatorFitness = lru::LruCache<CollatorId, CollatorFitnessMetric>;

pub(crate) type Reservoir = HashMap<PeerId, PeerData>;

pub struct PeerSlots {
	seq_nr: u64,
	pub(crate) fitness: CollatorFitness,
	pub(crate) peer_data: Reservoir,
	pub(crate) active_paras: ActiveParas,
	stale_peers: Vec<PeerId>,
}

impl Default for PeerSlots {
	fn default() -> Self {
		Self {
			seq_nr: 0u64,
			fitness: lru::LruCache::new(CACHE_SIZE),
			peer_data: HashMap::new(),
			active_paras: ActiveParas::default(),
			stale_peers: Vec::new(),
		}
	}
}

impl std::fmt::Debug for PeerSlots {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "Eladed")
	}
}

impl PeerSlots {
	pub fn insert_collator(&mut self, collator_id: &CollatorId) {
		if self.fitness.get(collator_id).is_none() {
			self.fitness.put(collator_id.clone(), CollatorFitnessMetric::default());
		}
	}

	pub fn stale_peers(&mut self) -> Vec<PeerId> {
		self.stale_peers.drain(0..).collect()
	}

	pub fn reset_sample(&mut self) {
		self.seq_nr = 0;
	}
}

pub(crate) fn handle_view_change(peer_slots: &mut PeerSlots, view: &View) {
	for (peer_id, peer_data) in peer_slots.peer_data.iter_mut() {
		peer_data.prune_old_advertisements(view);

		if let Some(para_id) = peer_data.collating_para() {
			if !peer_slots.active_paras.is_current_or_next(para_id) {
				 peer_slots.stale_peers.push(*peer_id);
			}
		}
	}
}

pub(crate) async fn cycle_para(
	sender: &mut impl SubsystemSender,
	active_paras: &mut ActiveParas,
	keystore: &SyncCryptoStorePtr,
	new_relay_parents: impl IntoIterator<Item = Hash>,
	old_relay_parents: impl IntoIterator<Item = Hash>,
) {
	active_paras.assign_incoming(sender, keystore, new_relay_parents).await;
	active_paras.remove_outgoing(old_relay_parents);
}

fn peers_to_evict(peer_data: &Reservoir, fitness: &mut CollatorFitness, num: usize, rng: &mut ThreadRng) -> Vec<PeerId> {
	let mut fitted_reservoir = Vec::new();
	// Traverse list of peers
	for (peer_id, peer_data) in peer_data.iter() {
		// Get collator id
		if let Some(collator_id) = peer_data.collator_id() {
			// Get fitness metric
			if let Some(metric) = fitness.get(collator_id) {
				fitted_reservoir.push((*peer_id, metric.compute_fitness()));
			} else {
				// If the peer is not known to our validator node, we should only evict them if
				// our reservoir is oversubscribed, so we assign them a fitness of 0 (less is
				// better)
				fitted_reservoir.push((*peer_id, 0f64));
			}
		}
	}
	// Shuffle and then sort our fitted reservoir by reverse fitness.
	// Note that we should ensure that this sorting includes randomization for all-things-equal
	// peers. We can explore a better solution when optimizing the PeerSlots data structure.
	fitted_reservoir.shuffle(rng);
	fitted_reservoir.sort_by(|a, b| {
		if a.1 < b.1 {
			std::cmp::Ordering::Greater
		} else {
			std::cmp::Ordering::Less
		}
	});
	// Take the peers we must evict
	fitted_reservoir.iter().map(|a| a.0)
		.take(num)
		.collect()
}

// Reservoir sampling is a randomized algorithm that allows to maintain a reservoir of fixed size k
// along with a sequence number in order to iteratively fill the reservoir with elements over an
// incoming stream such that at any given point in time the elements in the reservoir were
// k-choose-seq_nr-uniformly randomly selected among the events accepted off the stream.
// By incrementing the sequence number after each sample, we ensure the the reservoir of size k
// has been chosen k-choose-seq_nr-uniformly at random among all viable collators since the seq_nr
// was reset in the previous parachain assignment.
//
// That is, for each collator we generate a random number between 0 and the sampler's seq_nr.
//
// If that random number is lower than the size of our reservoir we evict a random other peer.
// If that random number is greater than the size of our reservoir, we evict the declaring
// peer.
//
// We must reset this seq_nr after every view change in order to ensure that we enforce a
// uniform random distribution over connecting and declaring collators for the parachains that
// are relevant at the time of the random sample.
pub async fn sample_connection(
	peer_slots: &mut PeerSlots,
	peer_id: &PeerId,
	collator_id: &CollatorId,
) -> Vec<PeerId> {
	// Since we cannot intercept incoming connections yet, we must remove the connected peer from
	// peer_data in order to ensure we do not accidentally schedule them for eviction unless they
	// are not sampled for this seq_nr's reservoir
	//
	// To that effect, we will remove the peer from peer_data and insert them back after we've
	// sampled our eviction candidates
	if let Some(peer_data) = peer_slots.peer_data.remove(peer_id) {
		// Increment seq_nr in order to ensure that the sample probability for peer_id to be
		// included in this reservoir is k/seq_nr.
		peer_slots.seq_nr += 1;
		// Insert collator into our fitness metrics if it does not exist yet.
		peer_slots.insert_collator(collator_id);
		// Determine how many peer we need to evict
		let mut surplus_peers = peer_slots.peer_data.len().saturating_sub(RESERVOIR_SIZE - 1);

		// Evict all stale peers, regardless of metrics or sample
		let mut out: Vec<PeerId> = peer_slots.stale_peers.drain(0..surplus_peers).collect();

		let mut rng = thread_rng();

		// If we must evict additional peers, then we will need to determine the most suitable
		// peers to evict, i.e. the ones with the worst metrics.
		//
		// The below function is O(n*log(n)) as we naively sort the list of peers, but this can be
		// optimized by modifying the PeerSlots struct to leverage a linked list
		surplus_peers = surplus_peers.saturating_sub(out.len());
		if surplus_peers > RESERVOIR_SIZE - 1 {
			out.extend_from_slice(peers_to_evict(&peer_slots.peer_data, &mut peer_slots.fitness, surplus_peers, &mut rng).as_slice());
		} else {
			// If the reservoir is not full, we only evict stale peers
			peer_slots.peer_data.insert(*peer_id, peer_data);
			return out;
		}

		// If there is at least one element in the output, then we know we must sample
		// the Declaring Collator into our reservoir
		out.shuffle(&mut rng);
		if let Some(available_slot) = out.pop() {
			if (rng.gen_range(0..peer_slots.seq_nr) as usize) < CACHE_SIZE {
				out.push(available_slot);
			} else {
				out.push(*peer_id);
			}
		}
		peer_slots.peer_data.insert(*peer_id, peer_data);

		return out;
	}

	vec![]
}

pub async fn insert_event<Context>(
	ctx: &mut Context,
	peer_slots: &mut PeerSlots,
	peer_id: &PeerId,
	collator_id: &CollatorId,
	event: FitnessEvent,
) where
	Context: SubsystemContext<Message = CollatorProtocolMessage>,
{
	modify_reputation(ctx, *peer_id, COLLATOR_METRICS[event as usize]).await;
	if let Some(metric) = peer_slots.fitness.get_mut(collator_id) {
		metric.insert_event(event);
	} else {
		let mut metric = CollatorFitnessMetric::default();
		metric.insert_event(event);
		peer_slots.fitness.put(collator_id.clone(), metric);
	}
}

/// Modify the reputation of a peer based on its behavior.
#[tracing::instrument(level = "trace", skip(ctx), fields(subsystem = LOG_TARGET))]
async fn modify_reputation<Context>(ctx: &mut Context, peer: PeerId, rep: Rep)
where
	Context: SubsystemContext,
{
	tracing::trace!(
		target: LOG_TARGET,
		rep = ?rep,
		peer_id = %peer,
		"reputation change for peer",
	);

	ctx.send_message(AllMessages::NetworkBridge(
		NetworkBridgeMessage::ReportPeer(peer, rep),
	)).await;
}
