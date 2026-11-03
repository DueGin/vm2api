-- 900_fork_proxy_geo_asn — AS number of each proxy's observed exit.
--
-- Fork-only migration, numbered out of upstream's sequence on purpose: the
-- runner keys versions by the numeric prefix, so a fork `048_*` would collide
-- with upstream's next `048_*` (checksum mismatch at boot). Upstream code that
-- does not know this column ignores it; ProxiesRepo writes only listed columns.
--
-- geo_asn is `AS<number>` from the geo lookup (ip-api `as`). Two bound exits on
-- one AS are reported to the operator, never refused. geo_isp keeps its plain
-- ISP text: it is mirrored into native telemetry and must not change shape.

ALTER TABLE proxies ADD COLUMN geo_asn TEXT;
