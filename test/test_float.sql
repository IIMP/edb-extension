-- 13 KrQq+con4lOWmsXNoQxjke2Mowm/2nOZTiCqKbIZGVY=
-- 5 YYCfYlz2a1lNfVsr3s8STiOHIAuX9zKJvRHekcpO8Zg=
-- 18 koHrD684Lp5PFn4htXVyUCqe/wOq1WOFDFSn5iPKql4=
-- 8 H4/RaE+u4PKPK582NJ/k5ZknsJX1KWLZKdfYmVKaNxc=
-- 65 s+EFCGDeRWBZhiyegMgszhjJRbX9DY/dPiUkEJDkWCE=
-- 2.6 JLO39iNrvBY49J9C3uyTJfs8isNjKLBYiGlUEq6+FNI=
-- 3 VFVbR0AT24HmpjEoONBRKXhJEVg4eNy2IrFKYcpyAko=
-- 371293 7eMll25ttNcjzyOTdj6SXNy9V0TqDQcEkIInx29fxRc=
----------------------------------------------------------
-- 109 HGkzc8prr3DCmrSY1aFLG13HPMzZqI/yJSa1TkDxhOA=
-- 21.8 95IGwMlJDB8bNy+IGblLi6ou/F2dbBRm0w3Kb8rJ9jg=

-- 13 + 5 = 18
SELECT ('KrQq+con4lOWmsXNoQxjke2Mowm/2nOZTiCqKbIZGVY='::edb_float4 + 'YYCfYlz2a1lNfVsr3s8STiOHIAuX9zKJvRHekcpO8Zg='::edb_float4) = 'koHrD684Lp5PFn4htXVyUCqe/wOq1WOFDFSn5iPKql4='::edb_float4;

-- 13 - 5 = 8
SELECT ('KrQq+con4lOWmsXNoQxjke2Mowm/2nOZTiCqKbIZGVY='::edb_float4 - 'YYCfYlz2a1lNfVsr3s8STiOHIAuX9zKJvRHekcpO8Zg='::edb_float4) = 'H4/RaE+u4PKPK582NJ/k5ZknsJX1KWLZKdfYmVKaNxc='::edb_float4;

-- 13 * 5 = 65
SELECT ('KrQq+con4lOWmsXNoQxjke2Mowm/2nOZTiCqKbIZGVY='::edb_float4 * 'YYCfYlz2a1lNfVsr3s8STiOHIAuX9zKJvRHekcpO8Zg='::edb_float4) = 's+EFCGDeRWBZhiyegMgszhjJRbX9DY/dPiUkEJDkWCE='::edb_float4;

-- 13 / 5 = 2.6
SELECT ('KrQq+con4lOWmsXNoQxjke2Mowm/2nOZTiCqKbIZGVY='::edb_float4 / 'YYCfYlz2a1lNfVsr3s8STiOHIAuX9zKJvRHekcpO8Zg='::edb_float4) = 'JLO39iNrvBY49J9C3uyTJfs8isNjKLBYiGlUEq6+FNI='::edb_float4;

-- 13 % 5 = 3
SELECT ('KrQq+con4lOWmsXNoQxjke2Mowm/2nOZTiCqKbIZGVY='::edb_float4 % 'YYCfYlz2a1lNfVsr3s8STiOHIAuX9zKJvRHekcpO8Zg='::edb_float4) = 'VFVbR0AT24HmpjEoONBRKXhJEVg4eNy2IrFKYcpyAko='::edb_float4;

-- 13 ^ 5 = 371293
SELECT ('KrQq+con4lOWmsXNoQxjke2Mowm/2nOZTiCqKbIZGVY='::edb_float4 ^ 'YYCfYlz2a1lNfVsr3s8STiOHIAuX9zKJvRHekcpO8Zg='::edb_float4) = '7eMll25ttNcjzyOTdj6SXNy9V0TqDQcEkIInx29fxRc='::edb_float4;


-- 5 = 5
SELECT 'YYCfYlz2a1lNfVsr3s8STiOHIAuX9zKJvRHekcpO8Zg='::edb_float4 = 'YYCfYlz2a1lNfVsr3s8STiOHIAuX9zKJvRHekcpO8Zg='::edb_float4;

-- 13 = 13
SELECT 'KrQq+con4lOWmsXNoQxjke2Mowm/2nOZTiCqKbIZGVY='::edb_float4 = 'KrQq+con4lOWmsXNoQxjke2Mowm/2nOZTiCqKbIZGVY='::edb_float4;

-- 5 <> 13
SELECT 'YYCfYlz2a1lNfVsr3s8STiOHIAuX9zKJvRHekcpO8Zg='::edb_float4 <> 'KrQq+con4lOWmsXNoQxjke2Mowm/2nOZTiCqKbIZGVY='::edb_float4;

-- 5 < 13
SELECT 'YYCfYlz2a1lNfVsr3s8STiOHIAuX9zKJvRHekcpO8Zg='::edb_float4 < 'KrQq+con4lOWmsXNoQxjke2Mowm/2nOZTiCqKbIZGVY='::edb_float4;

-- 5 <= 13
SELECT 'YYCfYlz2a1lNfVsr3s8STiOHIAuX9zKJvRHekcpO8Zg='::edb_float4 <= 'KrQq+con4lOWmsXNoQxjke2Mowm/2nOZTiCqKbIZGVY='::edb_float4;

-- 13 > 5
SELECT 'KrQq+con4lOWmsXNoQxjke2Mowm/2nOZTiCqKbIZGVY='::edb_float4 > 'YYCfYlz2a1lNfVsr3s8STiOHIAuX9zKJvRHekcpO8Zg='::edb_float4;

-- 13 >= 5
SELECT 'KrQq+con4lOWmsXNoQxjke2Mowm/2nOZTiCqKbIZGVY='::edb_float4 >= 'YYCfYlz2a1lNfVsr3s8STiOHIAuX9zKJvRHekcpO8Zg='::edb_float4;


DROP TABLE IF exists test_float_agg;
CREATE TABLE test_float_agg(
    value edb_float4 not null
);

INSERT INTO test_float_agg(value) VALUES
    ('KrQq+con4lOWmsXNoQxjke2Mowm/2nOZTiCqKbIZGVY='),
    ('YYCfYlz2a1lNfVsr3s8STiOHIAuX9zKJvRHekcpO8Zg='),
    ('koHrD684Lp5PFn4htXVyUCqe/wOq1WOFDFSn5iPKql4='),
    ('H4/RaE+u4PKPK582NJ/k5ZknsJX1KWLZKdfYmVKaNxc='),
    ('s+EFCGDeRWBZhiyegMgszhjJRbX9DY/dPiUkEJDkWCE=');

SELECT MIN(value) = 'YYCfYlz2a1lNfVsr3s8STiOHIAuX9zKJvRHekcpO8Zg='::edb_float4 FROM test_float_agg;
SELECT MAX(value) = 's+EFCGDeRWBZhiyegMgszhjJRbX9DY/dPiUkEJDkWCE='::edb_float4 FROM test_float_agg;
SELECT SUM(value) = 'HGkzc8prr3DCmrSY1aFLG13HPMzZqI/yJSa1TkDxhOA='::edb_float4 FROM test_float_agg;
SELECT AVG(value) = '95IGwMlJDB8bNy+IGblLi6ou/F2dbBRm0w3Kb8rJ9jg='::edb_float4 FROM test_float_agg;

DROP TABLE IF exists test_float_agg;
