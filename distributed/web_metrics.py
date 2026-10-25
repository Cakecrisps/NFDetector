"""Bounded administrative views. Sensor credentials cannot access these queries."""


def overview(store):
    with store.connect() as conn:
        agents = conn.execute('''SELECT count(*) AS total,
            count(*) FILTER (WHERE NOT revoked AND last_seen_at>clock_timestamp()-interval '60 seconds') AS online,
            count(*) FILTER (WHERE revoked) AS revoked FROM nf_agents''').fetchone()
        traffic = conn.execute('''SELECT count(*) AS files,COALESCE(sum(size),0) AS received_bytes,
            COALESCE(sum(frames),0) AS packets,COALESCE(sum(captured_bytes),0) AS captured_bytes,
            count(*) FILTER (WHERE status IN ('pending','parsing')) AS queued,
            count(*) FILTER (WHERE status='error') AS failed,
            count(*) FILTER (WHERE status='ready' AND captured_bytes IS NULL) AS legacy_files FROM nf_chunks''').fetchone()
        alerts = conn.execute('''SELECT count(*) AS total,
            count(*) FILTER (WHERE to_timestamp(last_seen)>clock_timestamp()-interval '24 hours' AND kind<>'DECODE_WARNING') AS last_day,
            count(*) FILTER (WHERE kind='DECODE_WARNING') AS decode_warnings FROM nf_incidents''').fetchone()
        domains = conn.execute('''SELECT id,last_timestamp,error,
            owner IS NOT NULL AND lease_until>clock_timestamp() AS processing,
            work_version>completed_version AS pending FROM nf_domains ORDER BY id LIMIT 100''').fetchall()
        workers = conn.execute('''SELECT kind,count(*) AS online FROM nf_workers
            WHERE last_seen_at>clock_timestamp()-interval '30 seconds' GROUP BY kind''').fetchall()
    return dict(agents=agents, traffic=traffic, alerts=alerts, domains=domains,
                workers={row['kind']: row['online'] for row in workers})


def traffic(store, hours=24):
    with store.connect() as conn:
        timeline = conn.execute('''WITH hours AS (
            SELECT generate_series(date_trunc('hour',clock_timestamp())-((%s-1)*interval '1 hour'),
                date_trunc('hour',clock_timestamp()),interval '1 hour') AS hour
            ), arrivals AS (
            SELECT date_trunc('hour',created_at) AS hour,sum(size) AS bytes,
                COALESCE(sum(frames),0) AS packets,count(*) AS files FROM nf_chunks
            WHERE created_at>date_trunc('hour',clock_timestamp())-((%s-1)*interval '1 hour') GROUP BY 1)
            SELECT h.hour,COALESCE(a.bytes,0) AS bytes,COALESCE(a.packets,0) AS packets,
                COALESCE(a.files,0) AS files FROM hours h LEFT JOIN arrivals a USING(hour) ORDER BY h.hour''',
                                (hours, hours)).fetchall()
        protocols = conn.execute('''SELECT p.key AS protocol,sum(p.value::bigint) AS packets FROM nf_chunks c,
            LATERAL jsonb_each_text(COALESCE(c.traffic_stats->'protocols','{}'::jsonb)) p
            GROUP BY p.key ORDER BY packets DESC LIMIT 12''').fetchall()
        event_types = conn.execute('''SELECT kind,count(*) AS count
            FROM nf_incidents WHERE to_timestamp(last_seen)>clock_timestamp()-(%s*interval '1 hour')
            GROUP BY 1 ORDER BY count DESC LIMIT 20''', (hours,)).fetchall()
    return dict(timeline=timeline, protocols=protocols, event_types=event_types)


def agents(store, query='', offset=0, limit=100):
    pattern = '%' + query + '%'
    with store.connect() as conn:
        total = conn.execute('SELECT count(*) AS count FROM nf_agents WHERE name ILIKE %s OR domain ILIKE %s',
                             (pattern, pattern)).fetchone()['count']
        rows = conn.execute('''SELECT a.id,a.name,a.domain,a.key_id,a.revoked,a.created_at,a.last_seen_at,a.last_heartbeat_at,
            a.capture_state,a.backlog_bytes,a.backlog_files,a.software_version,a.last_error,
            CASE WHEN a.revoked THEN 'revoked' WHEN a.last_seen_at IS NULL THEN 'never_seen'
                WHEN a.last_seen_at<clock_timestamp()-interval '60 seconds' THEN 'offline'
                WHEN a.capture_state='error' THEN 'error' ELSE 'online' END AS status,
            COALESCE(t.files,0) AS files,COALESCE(t.bytes,0) AS received_bytes,
            COALESCE(t.packets,0) AS packets,COALESCE(t.queued,0) AS queued,
            COALESCE(t.failed,0) AS failed,t.last_upload FROM nf_agents a
            LEFT JOIN LATERAL (SELECT count(*) AS files,sum(c.size) AS bytes,sum(c.frames) AS packets,
                count(*) FILTER (WHERE c.status IN ('pending','parsing')) AS queued,
                count(*) FILTER (WHERE c.status='error') AS failed,max(c.created_at) AS last_upload
                FROM nf_streams s JOIN nf_chunks c ON c.stream_id=s.id WHERE s.agent_id=a.id) t ON true
            WHERE a.name ILIKE %s OR a.domain ILIKE %s ORDER BY a.created_at DESC,a.id LIMIT %s OFFSET %s''',
                            (pattern, pattern, limit, offset)).fetchall()
    return dict(agents=rows, total=total, offset=offset, limit=limit)


def streams(store, agent_id):
    with store.connect() as conn:
        return conn.execute('''SELECT s.id,s.interface,s.started_at,s.created_at,s.last_sequence,s.processed_sequence,
            count(c.id) AS files,count(c.id) FILTER (WHERE c.status='error') AS failed,
            COALESCE(sum(c.size),0) AS received_bytes FROM nf_streams s LEFT JOIN nf_chunks c ON c.stream_id=s.id
            WHERE s.agent_id=%s GROUP BY s.id ORDER BY s.created_at DESC LIMIT 50''', (agent_id,)).fetchall()


def events(store, kind='', query='', offset=0, limit=50):
    conditions = ["(%s='' OR i.kind=%s OR %s=ANY(i.kinds))",
        '''(i.source ILIKE %s OR i.target ILIKE %s OR i.reason ILIKE %s OR EXISTS (
            SELECT 1 FROM nf_incident_streams p JOIN nf_streams ps ON ps.id=p.stream_id
            JOIN nf_agents pa ON pa.id=ps.agent_id WHERE p.incident_id=i.id AND pa.name ILIKE %s)
            OR EXISTS(SELECT 1 FROM unnest(i.sources) ip WHERE ip ILIKE %s))''']
    where = ' AND '.join(conditions)
    pattern = '%' + query + '%'
    parameters = (kind, kind, kind, pattern, pattern, pattern, pattern, pattern)
    with store.connect() as conn:
        total = conn.execute('SELECT count(*) AS count FROM nf_incidents i WHERE ' + where, parameters).fetchone()['count']
        rows = conn.execute('''SELECT i.id,i.first_seen AS timestamp,i.created_at,i.updated_at,i.reason,
            COALESCE(NULLIF(i.source,''),i.sources[1],'') AS source,i.sources,i.sources_truncated,i.target,i.stream_id,
            i.sequence,i.packet_index,i.domain,i.kind,i.kinds,i.service,i.first_seen,i.last_seen,
            i.last_seen-i.first_seen AS duration_seconds,i.signal_count,i.closed_at,i.close_reason,
            CASE WHEN i.closed_at IS NOT NULL THEN 'closed'
                WHEN d.error IS NOT NULL OR to_timestamp(d.last_timestamp)<clock_timestamp()-(%s*interval '1 second')
                THEN 'awaiting_data' ELSE 'active' END AS status,
            a.name AS agent_name,a.id AS agent_id
            FROM nf_incidents i JOIN nf_streams s ON s.id=i.stream_id JOIN nf_agents a ON a.id=s.agent_id
            JOIN nf_domains d ON d.id=i.domain
            WHERE ''' + where + ' ORDER BY i.last_seen DESC,i.id LIMIT %s OFFSET %s',
                            (max(60, store.settings.incident_gap_seconds), *parameters, limit, offset)).fetchall()
    return dict(events=rows, total=total, offset=offset, limit=limit, incident_gap_seconds=store.settings.incident_gap_seconds)
