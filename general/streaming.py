"""Incremental detectors: keep timestamps and keys, never decoded packets."""
from collections import Counter, deque
from heapq import nlargest


class CountWindow:
    def __init__(self, seconds, limit):
        self.seconds = seconds
        self.limit = limit
        self.events = deque()
        self.counts = Counter()

    def expire(self, now):
        while self.events and self.events[0][0] < now - self.seconds:
            _, key, amount = self.events.popleft()
            self.counts[key] -= amount
            if not self.counts[key]:
                del self.counts[key]

    def add(self, timestamp, key, amount=1):
        previous = self.counts[key]
        self.events.append((timestamp, key, amount))
        self.counts[key] += amount
        return previous < self.limit <= self.counts[key]


class BeaconWindow:
    """Running interval sum and monotone queues for interval extrema."""
    def __init__(self):
        self.times = deque()
        self.intervals = deque()
        self.minimum = deque()
        self.maximum = deque()
        self.interval_sum = 0.0
        self.sequence = 0

    def add(self, timestamp):
        if self.times:
            self.sequence += 1
            item = (self.sequence, timestamp - self.times[-1])
            self.intervals.append(item)
            self.interval_sum += item[1]
            while self.minimum and self.minimum[-1][1] >= item[1]:
                self.minimum.pop()
            while self.maximum and self.maximum[-1][1] <= item[1]:
                self.maximum.pop()
            self.minimum.append(item)
            self.maximum.append(item)
        self.times.append(timestamp)

    def expire(self, cutoff):
        while self.times and self.times[0] < cutoff:
            self.times.popleft()
            if self.intervals:
                index, interval = self.intervals.popleft()
                self.interval_sum -= interval
                for queue in (self.minimum, self.maximum):
                    if queue and queue[0][0] == index:
                        queue.popleft()

    def matches(self, config):
        if len(self.times) < config.get('min_consistent_connections', 5) or len(self.intervals) < 2:
            return False
        average = self.interval_sum / len(self.intervals)
        return (config.get('interval_min_sec', 10) <= average <= config.get('interval_max_sec', 300)
                and self.maximum[0][1] - self.minimum[0][1] <= config.get('jitter_sec', 5))


class StreamingDetector:
    """One ordered capture stream. Emit rate alarms on threshold crossings.

    State is scoped to an observation domain. Disjoint sensor streams may be
    merged in event-time order upstream. Late packets are rejected before state
    is changed.
    """
    def __init__(self, analyzer):
        self.rules = analyzer.rules
        self.protected = set(analyzer.protectips)
        self.suspicious = analyzer.suspicious_ips
        self.stats = analyzer.stats
        self.last_timestamp = None
        self.rates = {}
        ddos = self.rules.get('ddos', {})
        flood = self.rules.get('flood', {})
        brute = self.rules.get('brute_force', {})
        if ddos.get('enabled') and '1ip' in ddos:
            config = ddos['1ip']
            self.rates['ddos'] = CountWindow(config.get('request_limit_window', 1), config.get('request_limit', 1000))
        if flood.get('enabled') and 'HTTP' in flood:
            config = flood['HTTP']
            self.rates['http'] = CountWindow(config.get('request_rate_window', 1), config.get('request_rate_limit', 80))
        if brute.get('enabled'):
            self.rates['brute'] = CountWindow(brute.get('tryes_limit_window', 20), brute.get('tryes_limit', 10))
            ssh = brute.get('ssh_handshakes', {})
            if 'SSH' in brute.get('auth_proto', []) and ssh.get('enabled', True):
                self.rates['ssh'] = CountWindow(ssh.get('window', brute.get('tryes_limit_window', 20)),
                                               ssh.get('limit', brute.get('tryes_limit', 10)))
        self.multi_config = ddos.get('nip') if ddos.get('enabled') else None
        self.multi_events = deque()
        self.multi_sources = {}
        self.multi_totals = Counter()
        self.multi_active = set()
        self.syn_config = flood.get('SYN') if flood.get('enabled') else None
        self.syn_events = deque()
        self.pending_syns = {}
        self.syn_counts = Counter()
        self.beacon_config = self.rules.get('C2_analysys', {}).get('beaconing_detection', {})
        if not self.rules.get('C2_analysys', {}).get('enabled'):
            self.beacon_config = {}
        self.beacon_events = deque()
        self.beacons = {}
        self.beacon_active = set()

    def _alarm(self, alarms, category, reason, target, source):
        self.stats['alarms'][category] += 1
        alarms.append((reason, target, source, True))

    def _multi_ready(self, target):
        return (len(self.multi_sources.get(target, {})) >= 2
                and self.multi_totals[target] >= self.multi_config.get('request_limit', 5000))

    def _expire(self, now):
        for window in self.rates.values():
            window.expire(now)
        if self.multi_config is not None:
            cutoff = now - self.multi_config.get('request_limit_window', 1)
            while self.multi_events and self.multi_events[0][0] < cutoff:
                _, target, source = self.multi_events.popleft()
                sources = self.multi_sources[target]
                sources[source] -= 1
                self.multi_totals[target] -= 1
                if not sources[source]:
                    del sources[source]
                if not sources:
                    del self.multi_sources[target]
                    del self.multi_totals[target]
                if not self._multi_ready(target):
                    self.multi_active.discard(target)
        if self.syn_config is not None:
            cutoff = now - self.syn_config.get('syn_only_window', 5)
            while self.syn_events and self.syn_events[0][0] < cutoff:
                timestamp, connection = self.syn_events.popleft()
                if self.pending_syns.get(connection) == timestamp:
                    self._remove_syn(connection)
        if self.beacon_config.get('enabled'):
            cutoff = now - self.beacon_config.get('interval_max_sec', 300)
            while self.beacon_events and self.beacon_events[0][0] < cutoff:
                _, pair = self.beacon_events.popleft()
                state = self.beacons.get(pair)
                if state is None:
                    continue
                state.expire(cutoff)
                if not state.matches(self.beacon_config):
                    self.beacon_active.discard(pair)
                if not state.times:
                    del self.beacons[pair]

    def _remove_syn(self, connection):
        del self.pending_syns[connection]
        pair = connection[:2]
        self.syn_counts[pair] -= 1
        if not self.syn_counts[pair]:
            del self.syn_counts[pair]

    def process(self, info, auth_protocol=None):
        if not info:
            return []
        now = info['timestamp']
        if self.last_timestamp is not None and now < self.last_timestamp:
            raise ValueError('Capture timestamps must be nondecreasing; use one detector per ordered source')
        self.last_timestamp = now
        self._expire(now)
        self.stats['total'] += 1
        alarms = []
        source, target = info['src_ip'], info['dst_ip']
        protected = target in self.protected
        if protected:
            for name, window in self.rates.items():
                amounts = [(None, 1)]
                if name == 'http':
                    amount = info.get('http_requests', int(info['is_http']))
                    amounts = [(None, amount)] if amount else []
                elif name == 'brute':
                    protocols = info.get('auth_protocols', [auth_protocol] if auth_protocol else [])
                    counts = Counter(protocols)
                    amounts = [(proto, count) for proto, count in counts.items()
                               if proto in self.rules['brute_force'].get('auth_proto', [])]
                elif name == 'ssh':
                    amount = info.get('ssh_greetings', 0)
                    amounts = [(None, amount)] if amount else []
                for proto, amount in amounts:
                    key = ((source, target, info['dst_port']) if name == 'ssh' else
                           (source, target, proto) if name == 'brute' else (source, target))
                    if window.add(now, key, amount):
                        if name == 'ssh':
                            self._alarm(alarms, 'bruteforce',
                                        f'BRUTEFORCE_SSH_HANDSHAKES: {source} -> {target}:{info["dst_port"]} '
                                        f'(suspected brute force: {window.counts[key]} client greetings '
                                        f'in {window.seconds}s, limit: {window.limit}; authentication outcome unknown)',
                                        target, source)
                            continue
                        category, label = {'ddos': ('ddos', 'DDoS_SINGLE_IP'),
                                           'http': ('flood', 'HTTP_FLOOD'),
                                           'brute': ('bruteforce', f'BRUTEFORCE_{proto}')}[name]
                        self._alarm(alarms, category,
                                    f'{label}: {source} -> {target} ({window.counts[key]} events, limit: {window.limit})', target, source)
            if self.multi_config is not None:
                self.multi_events.append((now, target, source))
                self.multi_sources.setdefault(target, Counter())[source] += 1
                self.multi_totals[target] += 1
                if self._multi_ready(target) and target not in self.multi_active:
                    self.multi_active.add(target)
                    for attacker, count in nlargest(self.multi_config.get('display_ips', 10),
                                                    self.multi_sources[target].items(), key=lambda item: item[1]):
                        self._alarm(alarms, 'ddos',
                                    f'DDoS_MULTI_IP: {attacker} sent {count} packets, total: {self.multi_totals[target]}', target, attacker)
        if self.syn_config is not None:
            self._syn(info, alarms)
        if protected and self.beacon_config.get('enabled'):
            pair = (source, target)
            state = self.beacons.get(pair)
            if state is None:
                state = self.beacons[pair] = BeaconWindow()
            state.add(now)
            self.beacon_events.append((now, pair))
            if state.matches(self.beacon_config):
                if pair not in self.beacon_active:
                    self.beacon_active.add(pair)
                    average = state.interval_sum / len(state.intervals)
                    self._alarm(alarms, 'c2', f'C2_BEACONING: {source} -> {target} (interval: {average:.1f}s)', target, source)
            else:
                self.beacon_active.discard(pair)
        if protected and self.rules.get('suspicious_ips', {}).get('enabled'):
            for address, label in ((source, 'SUSPICIOUS_SOURCE_IP'), (target, 'SUSPICIOUS_DEST_IP')):
                if address in self.suspicious:
                    self.stats['susp_ips'][address] = self.stats['susp_ips'].get(address, 0) + 1
                    self._alarm(alarms, 'susp_ips', f'{label}: {source} -> {target} (threat intel)', target, source)
        return alarms

    def _syn(self, info, alarms):
        source, target = info['src_ip'], info['dst_ip']
        srcport, dstport = info['src_port'], info['dst_port']
        if not srcport or not dstport:
            return
        if info['is_syn'] and target in self.protected:
            connection = (source, target, srcport, dstport)
            pair = (source, target)
            previous = self.syn_counts[pair]
            if connection not in self.pending_syns:
                self.syn_counts[pair] += 1
            self.pending_syns[connection] = info['timestamp']
            self.syn_events.append((info['timestamp'], connection))
            limit = self.syn_config.get('syn_only_limit', 50)
            if previous < limit <= self.syn_counts[pair]:
                self._alarm(alarms, 'flood', f'SYN_FLOOD_HALF_OPEN: {source} has {self.syn_counts[pair]} half-open connections', target, source)
        elif info['is_syn_ack'] and source in self.protected:
            connection = (target, source, dstport, srcport)
            if connection in self.pending_syns:
                self._remove_syn(connection)
