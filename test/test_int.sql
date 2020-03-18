-- 77 6QuzHjM9KC6VUdENLudDKqJZVHv/2BiFPCq7kQuua4c=
-- 3 ZlRCI8EMwSkpD1vo4zlv2KA3KmaZH9sBPJOFG6261F8=
-- 74 F4Xh7Epclpm6r5J7Z2PdcEHWDz0k8c+naupN/DFFVjc=
-- 80 EyhUppPzvC82jqnwih/RSekCx9fclsUiTX2Var4mTCE=
-- 231 Rp1c6rrc9XKgQnDLtxA1TWL9ZHQGU0ecgK2xrWLuEYQ=
-- 25 rU5tle2MYizh3n3WgzG3dAXkGtccwSNKqvu6syvu+wQ=
---------------------------------------------------
-- 490 bTlbO7W/LmzE2NOxQi2A1U2kEmwVeajAsD07rTRrKbA=
-- 81 uiAj53GB3zECPwzPyVslDmEDvGK7VSU4dLOP0FtMZkg=
-- 2 MLBIsLwee2LgkvvCE6j+Cbg2CaFm+uQf9uAo5hdTPzs=
-- 456533 EUinrezRA14SKjupeZl9chxUeHzf0GD2uxJSo0QND6E=


-- 77 + 3 = 80
SELECT ('6QuzHjM9KC6VUdENLudDKqJZVHv/2BiFPCq7kQuua4c='::edb_int4 + 'ZlRCI8EMwSkpD1vo4zlv2KA3KmaZH9sBPJOFG6261F8='::edb_int4) = 'EyhUppPzvC82jqnwih/RSekCx9fclsUiTX2Var4mTCE='::edb_int4;

-- 77 - 3 = 74
SELECT ('6QuzHjM9KC6VUdENLudDKqJZVHv/2BiFPCq7kQuua4c='::edb_int4 - 'ZlRCI8EMwSkpD1vo4zlv2KA3KmaZH9sBPJOFG6261F8='::edb_int4) = 'F4Xh7Epclpm6r5J7Z2PdcEHWDz0k8c+naupN/DFFVjc='::edb_int4;

-- 77 * 3 = 231
SELECT ('6QuzHjM9KC6VUdENLudDKqJZVHv/2BiFPCq7kQuua4c='::edb_int4 * 'ZlRCI8EMwSkpD1vo4zlv2KA3KmaZH9sBPJOFG6261F8='::edb_int4) = 'Rp1c6rrc9XKgQnDLtxA1TWL9ZHQGU0ecgK2xrWLuEYQ='::edb_int4;

-- 77 / 3 = 25
SELECT ('6QuzHjM9KC6VUdENLudDKqJZVHv/2BiFPCq7kQuua4c='::edb_int4 / 'ZlRCI8EMwSkpD1vo4zlv2KA3KmaZH9sBPJOFG6261F8='::edb_int4) = 'rU5tle2MYizh3n3WgzG3dAXkGtccwSNKqvu6syvu+wQ='::edb_int4;

-- 77 % 3 = 2
SELECT ('6QuzHjM9KC6VUdENLudDKqJZVHv/2BiFPCq7kQuua4c='::edb_int4 % 'ZlRCI8EMwSkpD1vo4zlv2KA3KmaZH9sBPJOFG6261F8='::edb_int4) = 'MLBIsLwee2LgkvvCE6j+Cbg2CaFm+uQf9uAo5hdTPzs='::edb_int4;

-- 77 ^ 3 = 456533
SELECT ('6QuzHjM9KC6VUdENLudDKqJZVHv/2BiFPCq7kQuua4c='::edb_int4 ^ 'ZlRCI8EMwSkpD1vo4zlv2KA3KmaZH9sBPJOFG6261F8='::edb_int4) = 'EUinrezRA14SKjupeZl9chxUeHzf0GD2uxJSo0QND6E='::edb_int4;


-- 77 = 77
SELECT '6QuzHjM9KC6VUdENLudDKqJZVHv/2BiFPCq7kQuua4c='::edb_int4 = '6QuzHjM9KC6VUdENLudDKqJZVHv/2BiFPCq7kQuua4c='::edb_int4;

-- 3 = 3
SELECT 'ZlRCI8EMwSkpD1vo4zlv2KA3KmaZH9sBPJOFG6261F8='::edb_int4 = 'ZlRCI8EMwSkpD1vo4zlv2KA3KmaZH9sBPJOFG6261F8='::edb_int4;

-- 77 <> 3
SELECT '6QuzHjM9KC6VUdENLudDKqJZVHv/2BiFPCq7kQuua4c='::edb_int4 <> 'ZlRCI8EMwSkpD1vo4zlv2KA3KmaZH9sBPJOFG6261F8='::edb_int4;

-- 3 < 77
SELECT 'ZlRCI8EMwSkpD1vo4zlv2KA3KmaZH9sBPJOFG6261F8='::edb_int4 < '6QuzHjM9KC6VUdENLudDKqJZVHv/2BiFPCq7kQuua4c='::edb_int4;
-- 3 <= 77
SELECT 'ZlRCI8EMwSkpD1vo4zlv2KA3KmaZH9sBPJOFG6261F8='::edb_int4 <= '6QuzHjM9KC6VUdENLudDKqJZVHv/2BiFPCq7kQuua4c='::edb_int4;

-- 77 > 3
SELECT '6QuzHjM9KC6VUdENLudDKqJZVHv/2BiFPCq7kQuua4c='::edb_int4 > 'ZlRCI8EMwSkpD1vo4zlv2KA3KmaZH9sBPJOFG6261F8='::edb_int4;

-- 77 >= 3
SELECT '6QuzHjM9KC6VUdENLudDKqJZVHv/2BiFPCq7kQuua4c='::edb_int4 >= 'ZlRCI8EMwSkpD1vo4zlv2KA3KmaZH9sBPJOFG6261F8='::edb_int4;


DROP TABLE IF exists test_int_agg;
CREATE TABLE test_int_agg(
    value edb_int4 not null
);

INSERT INTO test_int_agg(value) VALUES
    ('6QuzHjM9KC6VUdENLudDKqJZVHv/2BiFPCq7kQuua4c='),
    ('ZlRCI8EMwSkpD1vo4zlv2KA3KmaZH9sBPJOFG6261F8='),
    ('F4Xh7Epclpm6r5J7Z2PdcEHWDz0k8c+naupN/DFFVjc='),
    ('EyhUppPzvC82jqnwih/RSekCx9fclsUiTX2Var4mTCE='),
    ('Rp1c6rrc9XKgQnDLtxA1TWL9ZHQGU0ecgK2xrWLuEYQ='),
    ('rU5tle2MYizh3n3WgzG3dAXkGtccwSNKqvu6syvu+wQ=');

SELECT MIN(value) = 'ZlRCI8EMwSkpD1vo4zlv2KA3KmaZH9sBPJOFG6261F8='::edb_int4 FROM test_int_agg;
SELECT MAX(value) = 'Rp1c6rrc9XKgQnDLtxA1TWL9ZHQGU0ecgK2xrWLuEYQ='::edb_int4 FROM test_int_agg;
SELECT SUM(value) = 'bTlbO7W/LmzE2NOxQi2A1U2kEmwVeajAsD07rTRrKbA='::edb_int4 FROM test_int_agg;
SELECT AVG(value) = 'uiAj53GB3zECPwzPyVslDmEDvGK7VSU4dLOP0FtMZkg='::edb_int4 FROM test_int_agg;

DROP TABLE IF exists test_int_agg;
