CREATE TYPE edb_int4;

CREATE FUNCTION edb_int4_in(cstring) RETURNS edb_int4
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_int4_out(edb_int4) RETURNS cstring
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE TYPE edb_int4 (
    INPUT = edb_int4_in,
    OUTPUT = edb_int4_out
);


CREATE CAST (edb_int4 AS text) WITH INOUT AS ASSIGNMENT;
CREATE CAST (text AS edb_int4) WITH INOUT AS ASSIGNMENT;

CREATE FUNCTION edb_int4_add(edb_int4, edb_int4) RETURNS edb_int4
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_int4_sub(edb_int4, edb_int4) RETURNS edb_int4
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE OR REPLACE FUNCTION edb_int4_mul(edb_int4, edb_int4) RETURNS edb_int4
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_int4_div(edb_int4, edb_int4) RETURNS edb_int4
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_int4_mod(edb_int4, edb_int4) RETURNS edb_int4
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_int4_pow(edb_int4, edb_int4) RETURNS edb_int4
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_int4_lt(edb_int4, edb_int4) RETURNS boolean
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_int4_le(edb_int4, edb_int4) RETURNS boolean
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_int4_gt(edb_int4, edb_int4) RETURNS boolean
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_int4_ge(edb_int4, edb_int4) RETURNS boolean
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_int4_eq(edb_int4, edb_int4) RETURNS boolean
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_int4_ne(edb_int4, edb_int4) RETURNS boolean
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_int4_cmp(edb_int4, edb_int4) RETURNS integer
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_int4_sum_final(edb_int4[]) RETURNS edb_int4
    LANGUAGE C
    IMMUTABLE
    STRICT
    AS '$libdir/edb';

CREATE FUNCTION edb_int4_avg_final(edb_int4[]) RETURNS edb_int4
    LANGUAGE C
    IMMUTABLE
    STRICT
    AS '$libdir/edb';

CREATE FUNCTION edb_int4_min_final(edb_int4[]) RETURNS edb_int4
    LANGUAGE C
    IMMUTABLE
    STRICT
    AS '$libdir/edb';

CREATE FUNCTION edb_int4_max_final(edb_int4[]) RETURNS edb_int4
    LANGUAGE C
    IMMUTABLE
    STRICT
    AS '$libdir/edb';

CREATE AGGREGATE sum (edb_int4) (
   sfunc = array_append,
   stype = edb_int4[],
   finalfunc = edb_int4_sum_final
);

CREATE AGGREGATE avg (edb_int4) (
   sfunc = array_append,
   stype = edb_int4[],
   finalfunc = edb_int4_avg_final
);

CREATE AGGREGATE min (edb_int4) (
   sfunc = array_append,
   stype = edb_int4[],
   finalfunc = edb_int4_min_final
);

CREATE AGGREGATE max (edb_int4) (
   sfunc = array_append,
   stype = edb_int4[],
   finalfunc = edb_int4_max_final
);

CREATE OPERATOR < (
    LEFTARG = edb_int4,
    RIGHTARG = edb_int4,
    PROCEDURE = edb_int4_lt,
    COMMUTATOR = '>',
    NEGATOR = '>=',
    RESTRICT = scalarltsel,
    JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
    LEFTARG = edb_int4,
    RIGHTARG = edb_int4,
    PROCEDURE = edb_int4_le,
    COMMUTATOR = '>=',
    NEGATOR = '>',
    RESTRICT = scalarltsel,
    JOIN = scalarltjoinsel
);

CREATE OPERATOR > (
    LEFTARG = edb_int4,
    RIGHTARG = edb_int4,
    PROCEDURE = edb_int4_gt,
    COMMUTATOR = '<',
    NEGATOR = '<=',
    RESTRICT = scalargtsel,
    JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
    LEFTARG = edb_int4,
    RIGHTARG = edb_int4,
    PROCEDURE = edb_int4_ge,
    COMMUTATOR = '<=',
    NEGATOR = '<',
    RESTRICT = scalargtsel,
    JOIN = scalargtjoinsel
);

CREATE OPERATOR = (
    LEFTARG = edb_int4,
    RIGHTARG = edb_int4,
    PROCEDURE = edb_int4_eq,
    COMMUTATOR = '=',
    NEGATOR = '<>',
    RESTRICT = eqsel,
    JOIN = eqjoinsel,
    MERGES,
    HASHES
);

CREATE OPERATOR <> (
    LEFTARG = edb_int4,
    RIGHTARG = edb_int4,
    PROCEDURE = edb_int4_ne,
    COMMUTATOR = '<>',
    NEGATOR = '=',
    RESTRICT = neqsel,
    JOIN = neqjoinsel
);

CREATE OPERATOR + (
    LEFTARG = edb_int4,
    RIGHTARG = edb_int4,
    PROCEDURE = edb_int4_add
);

CREATE OPERATOR - (
    LEFTARG = edb_int4,
    RIGHTARG = edb_int4,
    PROCEDURE = edb_int4_sub
);

CREATE OPERATOR * (
    LEFTARG = edb_int4,
    RIGHTARG = edb_int4,
    PROCEDURE = edb_int4_mul
);

CREATE OPERATOR / (
    LEFTARG = edb_int4,
    RIGHTARG = edb_int4,
    PROCEDURE = edb_int4_div
);

CREATE OPERATOR % (
    LEFTARG = edb_int4,
    RIGHTARG = edb_int4,
    PROCEDURE = edb_int4_mod
);

CREATE OPERATOR ^ (
    LEFTARG = edb_int4,
    RIGHTARG = edb_int4,
    PROCEDURE = edb_int4_pow
);

CREATE OPERATOR CLASS edb_int4_btree_ops
DEFAULT FOR TYPE edb_int4 USING btree AS
        OPERATOR        1       <   ,
        OPERATOR        2       <=  ,
        OPERATOR        3       =   ,
        OPERATOR        4       >=  ,
        OPERATOR        5       >   ,
        FUNCTION        1       edb_int4_cmp(edb_int4, edb_int4);


-- CREATE OPERATOR CLASS edb_int4_sbtree_ops
-- DEFAULT FOR TYPE edb_int4 USING sbtree AS
        -- OPERATOR        1       <   ,
        -- OPERATOR        2       <=  ,
        -- OPERATOR        3       =   ,
        -- OPERATOR        4       >=  ,
        -- OPERATOR        5       >   ,
        -- FUNCTION        1       edb_int4_cmp(edb_int4, edb_int4);

CREATE TYPE edb_float4;

CREATE FUNCTION edb_float4_in(cstring) RETURNS edb_float4
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_float4_out(edb_float4) RETURNS cstring
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE TYPE edb_float4 (
    INPUT = edb_float4_in,
    OUTPUT = edb_float4_out
);


CREATE CAST (edb_float4 AS text) WITH INOUT AS ASSIGNMENT;
CREATE CAST (text AS edb_float4) WITH INOUT AS ASSIGNMENT;

CREATE FUNCTION edb_float4_add(edb_float4, edb_float4) RETURNS edb_float4
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_float4_sub(edb_float4, edb_float4) RETURNS edb_float4
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_float4_mul(edb_float4, edb_float4) RETURNS edb_float4
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_float4_div(edb_float4, edb_float4) RETURNS edb_float4
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_float4_mod(edb_float4, edb_float4) RETURNS edb_float4
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_float4_pow(edb_float4, edb_float4) RETURNS edb_float4
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_float4_lt(edb_float4, edb_float4) RETURNS boolean
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_float4_le(edb_float4, edb_float4) RETURNS boolean
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_float4_gt(edb_float4, edb_float4) RETURNS boolean
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_float4_ge(edb_float4, edb_float4) RETURNS boolean
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_float4_eq(edb_float4, edb_float4) RETURNS boolean
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_float4_ne(edb_float4, edb_float4) RETURNS boolean
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_float4_cmp(edb_float4, edb_float4) RETURNS integer
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_float4_sum_final(edb_float4[]) RETURNS edb_float4
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_float4_avg_final(edb_float4[]) RETURNS edb_float4
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_float4_min_final(edb_float4[]) RETURNS edb_float4
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_float4_max_final(edb_float4[]) RETURNS edb_float4
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE AGGREGATE sum (edb_float4) (
   sfunc = array_append,
   stype = edb_float4[],
   finalfunc = edb_float4_sum_final
);

CREATE AGGREGATE avg (edb_float4) (
   sfunc = array_append,
   stype = edb_float4[],
   finalfunc = edb_float4_avg_final
);

CREATE AGGREGATE min (edb_float4) (
   sfunc = array_append,
   stype = edb_float4[],
   finalfunc = edb_float4_min_final
);

CREATE AGGREGATE max (edb_float4) (
   sfunc = array_append,
   stype = edb_float4[],
   finalfunc = edb_float4_max_final
);

CREATE OPERATOR < (
    LEFTARG = edb_float4,
    RIGHTARG = edb_float4,
    PROCEDURE = edb_float4_lt,
    COMMUTATOR = '>',
    NEGATOR = '>=',
    RESTRICT = scalarltsel,
    JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
    LEFTARG = edb_float4,
    RIGHTARG = edb_float4,
    PROCEDURE = edb_float4_le,
    COMMUTATOR = '>=',
    NEGATOR = '>',
    RESTRICT = scalarltsel,
    JOIN = scalarltjoinsel
);

CREATE OPERATOR > (
    LEFTARG = edb_float4,
    RIGHTARG = edb_float4,
    PROCEDURE = edb_float4_gt,
    COMMUTATOR = '<',
    NEGATOR = '<=',
    RESTRICT = scalargtsel,
    JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
    LEFTARG = edb_float4,
    RIGHTARG = edb_float4,
    PROCEDURE = edb_float4_ge,
    COMMUTATOR = '<=',
    NEGATOR = '<',
    RESTRICT = scalargtsel,
    JOIN = scalargtjoinsel
);

CREATE OPERATOR = (
    LEFTARG = edb_float4,
    RIGHTARG = edb_float4,
    PROCEDURE = edb_float4_eq,
    COMMUTATOR = '=',
    NEGATOR = '<>',
    RESTRICT = eqsel,
    JOIN = eqjoinsel,
    MERGES,
    HASHES
);

CREATE OPERATOR <> (
    LEFTARG = edb_float4,
    RIGHTARG = edb_float4,
    PROCEDURE = edb_float4_ne,
    COMMUTATOR = '<>',
    NEGATOR = '=',
    RESTRICT = neqsel,
    JOIN = neqjoinsel
);

CREATE OPERATOR + (
    LEFTARG = edb_float4,
    RIGHTARG = edb_float4,
    PROCEDURE = edb_float4_add
);

CREATE OPERATOR - (
    LEFTARG = edb_float4,
    RIGHTARG = edb_float4,
    PROCEDURE = edb_float4_sub
);

CREATE OPERATOR * (
    LEFTARG = edb_float4,
    RIGHTARG = edb_float4,
    PROCEDURE = edb_float4_mul
);

CREATE OPERATOR / (
    LEFTARG = edb_float4,
    RIGHTARG = edb_float4,
    PROCEDURE = edb_float4_div
);

CREATE OPERATOR % (
    LEFTARG = edb_float4,
    RIGHTARG = edb_float4,
    PROCEDURE = edb_float4_mod
);

CREATE OPERATOR ^ (
    LEFTARG = edb_float4,
    RIGHTARG = edb_float4,
    PROCEDURE = edb_float4_pow
);

CREATE OPERATOR CLASS edb_float4_btree_ops
DEFAULT FOR TYPE edb_float4 USING btree AS
        OPERATOR        1       <   ,
        OPERATOR        2       <=  ,
        OPERATOR        3       =   ,
        OPERATOR        4       >=  ,
        OPERATOR        5       >   ,
        FUNCTION        1       edb_float4_cmp(edb_float4, edb_float4);

-- CREATE OPERATOR CLASS edb_float4_sbtree_ops
-- DEFAULT FOR TYPE edb_float4 USING sbtree AS
        -- OPERATOR        1       <   ,
        -- OPERATOR        2       <=  ,
        -- OPERATOR        3       =   ,
        -- OPERATOR        4       >=  ,
        -- OPERATOR        5       >   ,
        -- FUNCTION        1       edb_float4_cmp(edb_float4, edb_float4);

CREATE TYPE edb_text;

CREATE FUNCTION edb_text_in(cstring) RETURNS edb_text
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_text_out(edb_text) RETURNS cstring
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE TYPE edb_text (
    INPUT = edb_text_in,
    OUTPUT = edb_text_out
);


CREATE CAST (edb_text AS text) WITH INOUT AS ASSIGNMENT;
CREATE CAST (text AS edb_text) WITH INOUT AS ASSIGNMENT;

CREATE FUNCTION edb_text_lt(edb_text, edb_text) RETURNS boolean
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_text_le(edb_text, edb_text) RETURNS boolean
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_text_gt(edb_text, edb_text) RETURNS boolean
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_text_ge(edb_text, edb_text) RETURNS boolean
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_text_eq(edb_text, edb_text) RETURNS boolean
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_text_ne(edb_text, edb_text) RETURNS boolean
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_text_cmp(edb_text, edb_text) RETURNS integer
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_text_concat(edb_text, edb_text) RETURNS edb_text
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_text_like(edb_text, edb_text) RETURNS boolean
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';

CREATE FUNCTION edb_text_notlike(edb_text, edb_text) RETURNS boolean
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/edb';


CREATE OPERATOR < (
    LEFTARG = edb_text,
    RIGHTARG = edb_text,
    PROCEDURE = edb_text_lt,
    COMMUTATOR = '>',
    NEGATOR = '>=',
    RESTRICT = scalarltsel,
    JOIN = scalarltjoinsel
);

CREATE OPERATOR <= (
    LEFTARG = edb_text,
    RIGHTARG = edb_text,
    PROCEDURE = edb_text_le,
    COMMUTATOR = '>=',
    NEGATOR = '>',
    RESTRICT = scalarltsel,
    JOIN = scalarltjoinsel
);

CREATE OPERATOR > (
    LEFTARG = edb_text,
    RIGHTARG = edb_text,
    PROCEDURE = edb_text_gt,
    COMMUTATOR = '<',
    NEGATOR = '<=',
    RESTRICT = scalargtsel,
    JOIN = scalargtjoinsel
);

CREATE OPERATOR >= (
    LEFTARG = edb_text,
    RIGHTARG = edb_text,
    PROCEDURE = edb_text_ge,
    COMMUTATOR = '<=',
    NEGATOR = '<',
    RESTRICT = scalargtsel,
    JOIN = scalargtjoinsel
);

CREATE OPERATOR = (
    LEFTARG = edb_text,
    RIGHTARG = edb_text,
    PROCEDURE = edb_text_eq,
    COMMUTATOR = '=',
    NEGATOR = '<>',
    RESTRICT = eqsel,
    JOIN = eqjoinsel,
    MERGES,
    HASHES
);

CREATE OPERATOR <> (
    LEFTARG = edb_text,
    RIGHTARG = edb_text,
    PROCEDURE = edb_text_ne,
    COMMUTATOR = '<>',
    NEGATOR = '=',
    RESTRICT = neqsel,
    JOIN = neqjoinsel
);

CREATE OPERATOR || (
    LEFTARG = edb_text,
    RIGHTARG = edb_text,
    PROCEDURE = edb_text_concat
);

CREATE OPERATOR ~~ (
  LEFTARG = edb_text,
  RIGHTARG = edb_text,
  PROCEDURE = edb_text_like
);

CREATE OPERATOR !~~ (
  LEFTARG = edb_text,
  RIGHTARG = edb_text,
  PROCEDURE = edb_text_notlike
);

CREATE OPERATOR CLASS edb_text_btree_ops
DEFAULT FOR TYPE edb_text USING btree AS
        OPERATOR        1       <   ,
        OPERATOR        2       <=  ,
        OPERATOR        3       =   ,
        OPERATOR        4       >=  ,
        OPERATOR        5       >   ,
        FUNCTION        1       edb_text_cmp(edb_text, edb_text);

-- CREATE OPERATOR CLASS edb_text_sbtree_ops
-- DEFAULT FOR TYPE edb_text USING sbtree AS
        -- OPERATOR        1       <   ,
        -- OPERATOR        2       <=  ,
        -- OPERATOR        3       =   ,
        -- OPERATOR        4       >=  ,
        -- OPERATOR        5       >   ,
        -- FUNCTION        1       edb_text_cmp(edb_text, edb_text);
