-- ============================================================================
-- Extend the todo_items read model with the scalar fields the UI needs to
-- sort and filter WITHOUT opening the Loro document.
--
-- todo_items remains a DERIVED, class-(2) read model: it is rebuilt by replaying
-- the Loro doc (see store::rebuild_read_model). Tags and subtasks live
-- authoritatively in the doc; only `tags` is denormalized here (as JSON) for
-- cheap display/filtering. Subtasks are intentionally NOT projected here — they
-- are loaded from the doc on demand when an item is opened for editing.
--
-- `text` (from 0001) is the item TITLE. `priority` is an integer rank
-- (0=none, 1=low, 2=med, 3=high) so ORDER BY sorts most-urgent-last/first
-- without a lookup table. `due_at` is unix seconds (nullable) to match the
-- INTEGER/unixepoch() convention and index well for the meta-list range scans.
-- ============================================================================

ALTER TABLE todo_items ADD COLUMN due_at   INTEGER;                       -- unix seconds, NULL = no due date
ALTER TABLE todo_items ADD COLUMN priority INTEGER NOT NULL DEFAULT 0;    -- 0=none 1=low 2=med 3=high
ALTER TABLE todo_items ADD COLUMN notes    TEXT NOT NULL DEFAULT '';      -- free-text body
ALTER TABLE todo_items ADD COLUMN tags     TEXT NOT NULL DEFAULT '[]';    -- JSON array of strings (denormalized from the doc)

-- Meta-list scans ("Due Today/Week/Month") filter by due_at across ALL lists,
-- usually excluding done items; a partial index keeps it tight.
CREATE INDEX IF NOT EXISTS todo_items_due ON todo_items (due_at) WHERE done = 0;

-- Sorting a single list by priority.
CREATE INDEX IF NOT EXISTS todo_items_priority ON todo_items (list_id, priority);

PRAGMA user_version = 3;
