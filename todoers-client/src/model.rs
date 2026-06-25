//! Domain types for lists and todo items — the vocabulary shared by the Loro
//! document layer ([`crate::list_doc`]), local persistence ([`crate::db`]), the
//! store facade ([`crate::store`]), and the UI components.
//!
//! These are plain value types with small *pure* helpers (no I/O, no crypto), so
//! they stay trivially unit-testable. Due dates are carried as
//! [`time::OffsetDateTime`] in memory and persisted as unix seconds.

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use todoers_types::{ListId, Role};

/// Urgency rank for a todo item. The integer value is the sort key (higher =
/// more urgent), and it is what the `todo_items.priority` column stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    #[default]
    None,
    Low,
    Med,
    High,
}

impl Priority {
    /// Sort/storage rank: `none=0 .. high=3`.
    pub fn rank(self) -> i64 {
        match self {
            Priority::None => 0,
            Priority::Low => 1,
            Priority::Med => 2,
            Priority::High => 3,
        }
    }

    /// Inverse of [`Priority::rank`]; out-of-range values clamp to [`Priority::None`].
    pub fn from_rank(n: i64) -> Self {
        match n {
            1 => Priority::Low,
            2 => Priority::Med,
            3 => Priority::High,
            _ => Priority::None,
        }
    }

    /// Short human label for the UI.
    pub fn label(self) -> &'static str {
        match self {
            Priority::None => "—",
            Priority::Low => "low",
            Priority::Med => "med",
            Priority::High => "high",
        }
    }

    /// Cycle to the next priority (wraps high → none) for a press-to-change field.
    pub fn next(self) -> Self {
        Priority::from_rank((self.rank() + 1) % 4)
    }

    /// Cycle to the previous priority (wraps none → high).
    pub fn prev(self) -> Self {
        Priority::from_rank((self.rank() + 3) % 4)
    }
}

/// A single checklist entry nested under a [`TodoItem`]. Lives in the Loro doc;
/// loaded on demand (not projected into the SQLite read model).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subtask {
    /// Stable id (a Loro container/item id).
    pub id: String,
    pub title: String,
    pub done: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubtaskRow {
    pub item_id: String,
    /// Stable id (a Loro container/item id).
    pub id: String,
    pub title: String,
    pub done: bool,
}

impl From<SubtaskRow> for Subtask {
    fn from(row: SubtaskRow) -> Self {
        Self {
            id: row.id,
            title: row.title,
            done: row.done,
        }
    }
}

impl From<&SubtaskRow> for Subtask {
    fn from(row: &SubtaskRow) -> Self {
        Self {
            id: row.id.clone(),
            title: row.title.clone(),
            done: row.done,
        }
    }
}

/// A todo item as read out of the Loro document (the full record).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TodoItem {
    /// Stable id (the per-item Loro Map container id).
    pub id: String,
    pub title: String,
    pub notes: String,
    /// Optional due date; `None` means no due date set.
    #[serde(with = "time::serde::rfc3339::option")]
    pub due: Option<OffsetDateTime>,
    pub priority: Priority,
    pub done: bool,
    pub tags: Vec<String>,
    pub subtasks: Vec<Subtask>,
    /// Fractional position key for the MovableList ordering.
    pub order_key: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TodoItemRow {
    pub id: String,
    pub title: String,
    pub notes: String,
    pub due_at: Option<i64>,
    pub priority: i64,
    pub done: bool,
    pub tags: String, // raw JSON text
    pub order_key: String,
}

impl From<(TodoItemRow, Vec<Subtask>)> for TodoItem {
    fn from((row, subtasks): (TodoItemRow, Vec<Subtask>)) -> Self {
        Self {
            id: row.id,
            title: row.title,
            notes: row.notes,
            due: row
                .due_at
                .map(|ts| OffsetDateTime::from_unix_timestamp(ts).unwrap()),
            priority: Priority::from_rank(row.priority),
            done: row.done,
            tags: serde_json::from_str(&row.tags).unwrap_or_default(),
            order_key: row.order_key,
            subtasks,
        }
    }
}

impl From<(TodoItemRow, Vec<SubtaskRow>)> for TodoItem {
    fn from((row, subtasks): (TodoItemRow, Vec<SubtaskRow>)) -> Self {
        Self {
            id: row.id,
            title: row.title,
            notes: row.notes,
            due: row
                .due_at
                .map(|ts| OffsetDateTime::from_unix_timestamp(ts).unwrap()),
            priority: Priority::from_rank(row.priority),
            done: row.done,
            tags: serde_json::from_str(&row.tags).unwrap_or_default(),
            order_key: row.order_key,
            subtasks: subtasks.into_iter().map(Into::into).collect(),
        }
    }
}

/// The user-supplied fields when creating or editing a todo. Excludes machine
/// fields (`id`, `order_key`) that the doc/store assign.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TodoItemInput {
    pub title: String,
    pub notes: String,
    pub due: Option<OffsetDateTime>,
    pub priority: Priority,
    pub tags: Vec<String>,
}

/// Built-in aggregate views that span every list the user has locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetaList {
    AllTasks,
    DueToday,
    DueThisWeek,
    DueThisMonth,
}

impl MetaList {
    /// All meta-lists in display order (top of the sidebar).
    pub fn all() -> [MetaList; 4] {
        [
            MetaList::AllTasks,
            MetaList::DueToday,
            MetaList::DueThisWeek,
            MetaList::DueThisMonth,
        ]
    }

    pub fn label(self) -> &'static str {
        match self {
            MetaList::AllTasks => "All Tasks",
            MetaList::DueThisWeek => "Due this week",
            MetaList::DueToday => "Due Today",
            MetaList::DueThisMonth => "Due this month",
        }
    }

    /// Inclusive upper bound on an item's due date for this meta-list, given the
    /// current instant. `AllTasks` has no bound (returns `None`). The other
    /// variants are cumulative and include overdue items (anything due at or
    /// before the end of the period), so "Due this week" ⊇ "Due Today".
    pub fn due_before(self, now: OffsetDateTime) -> Option<OffsetDateTime> {
        let end_of_day = |d: OffsetDateTime| {
            d.replace_time(time::Time::from_hms(23, 59, 59).expect("valid time"))
        };
        match self {
            MetaList::AllTasks => None,
            MetaList::DueToday => Some(end_of_day(now)),
            MetaList::DueThisWeek => {
                // Days remaining until end of the current week (week ends Sunday).
                let from_monday = now.weekday().number_days_from_monday() as i64;
                Some(end_of_day(now + Duration::days(6 - from_monday)))
            }
            MetaList::DueThisMonth => {
                let last = time::util::days_in_month(now.month(), now.year()) as u8;
                Some(end_of_day(
                    now.replace_day(last).expect("valid day-of-month"),
                ))
            }
        }
    }

    /// Whether a todo with the given due date belongs in this meta-list as of
    /// `now`. Items with no due date appear only in `AllTasks`.
    pub fn contains(self, due: Option<OffsetDateTime>, now: OffsetDateTime) -> bool {
        match self.due_before(now) {
            None => true,
            Some(bound) => due.is_some_and(|d| d <= bound),
        }
    }
}

/// How to order tasks within a view (and, by aggregate, lists in the sidebar).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortMode {
    #[default]
    Alphabetical,
    DueDate,
    Priority,
}

impl SortMode {
    pub fn all() -> [SortMode; 3] {
        [
            SortMode::Alphabetical,
            SortMode::DueDate,
            SortMode::Priority,
        ]
    }

    pub fn label(self) -> &'static str {
        match self {
            SortMode::Alphabetical => "A–Z",
            SortMode::DueDate => "due date",
            SortMode::Priority => "priority",
        }
    }

    /// Cycle to the next sort mode (wraps), for a single toggle key.
    pub fn next(self) -> Self {
        let all = SortMode::all();
        let i = all.iter().position(|&m| m == self).unwrap_or(0);
        all[(i + 1) % all.len()]
    }
}

/// One user list as shown in the sidebar (lightweight summary, not the items).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListSummary {
    pub id: ListId,
    pub name: String,
    pub role: Role,
    /// Count of not-done items (for a sidebar badge).
    pub open_count: usize,
    /// Earliest due date among open items, if any (drives `SortMode::DueDate`).
    #[serde(with = "time::serde::rfc3339::option")]
    pub next_due: Option<OffsetDateTime>,
    /// Highest priority among open items (drives `SortMode::Priority`).
    pub top_priority: Priority,
}

/// A row in the sidebar: either a built-in meta-list or one of the user's lists.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SidebarEntry {
    Meta(MetaList),
    List(ListSummary),
}

/// Which view a pane is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViewTarget {
    Meta(MetaList),
    List(ListId),
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn priority_rank_round_trips_and_cycles() {
        for p in [Priority::None, Priority::Low, Priority::Med, Priority::High] {
            assert_eq!(Priority::from_rank(p.rank()), p);
        }
        assert_eq!(Priority::None.next(), Priority::Low);
        assert_eq!(Priority::High.next(), Priority::None);
        // Out-of-range ranks clamp to None.
        assert_eq!(Priority::from_rank(99), Priority::None);
    }

    #[test]
    fn sort_mode_cycles_through_all() {
        let mut m = SortMode::default();
        let seen: Vec<_> = (0..3)
            .map(|_| {
                let cur = m;
                m = m.next();
                cur
            })
            .collect();
        assert_eq!(seen, SortMode::all().to_vec());
        assert_eq!(m, SortMode::default(), "cycle wraps back to start");
    }

    #[test]
    fn metalist_bounds_are_cumulative() {
        // Wednesday 2026-06-17 12:00 UTC.
        let now = datetime!(2026-06-17 12:00:00 UTC);

        let today = MetaList::DueToday.due_before(now).unwrap();
        let week = MetaList::DueThisWeek.due_before(now).unwrap();
        let month = MetaList::DueThisMonth.due_before(now).unwrap();
        assert!(today <= week && week <= month, "today ⊆ week ⊆ month");

        // Week ends Sunday 2026-06-21; month ends 2026-06-30.
        assert_eq!(week.date(), time::macros::date!(2026 - 06 - 21));
        assert_eq!(month.date(), time::macros::date!(2026 - 06 - 30));
        assert!(MetaList::AllTasks.due_before(now).is_none());
    }

    #[test]
    fn metalist_contains_respects_due_and_overdue() {
        let now = datetime!(2026-06-17 12:00:00 UTC);
        let overdue = Some(datetime!(2026-06-01 09:00:00 UTC));
        let later_today = Some(datetime!(2026-06-17 20:00:00 UTC));
        let next_month = Some(datetime!(2026-07-15 09:00:00 UTC));

        // Overdue items surface in every dated meta-list (they need attention).
        assert!(MetaList::DueToday.contains(overdue, now));
        assert!(MetaList::DueToday.contains(later_today, now));
        assert!(!MetaList::DueToday.contains(next_month, now));
        assert!(!MetaList::DueThisMonth.contains(next_month, now));

        // No due date → only AllTasks.
        assert!(MetaList::AllTasks.contains(None, now));
        assert!(!MetaList::DueToday.contains(None, now));
    }
}
