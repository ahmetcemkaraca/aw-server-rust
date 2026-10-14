use aw_models::{QueryControl, ReportExecutionErrorV1};

#[test]
fn report_control_cancel_is_shared_between_stages() {
    let input = QueryControl::managed();
    let transform = input.clone();
    input.cancel();
    assert_eq!(
        transform.checkpoint(),
        Err(ReportExecutionErrorV1::Cancelled)
    );
    assert_eq!(
        transform.charge_rows(1),
        Err(ReportExecutionErrorV1::Cancelled)
    );
}

#[test]
fn report_control_rows_are_shared_across_periods() {
    let a = QueryControl::managed();
    let b = a.clone();
    a.charge_rows(125_000).unwrap();
    b.charge_rows(125_000).unwrap();
    assert_eq!(a.charge_rows(1), Err(ReportExecutionErrorV1::RowLimit));
    assert_eq!(a.stats().rows, 250_000);
    assert_eq!(b.checkpoint(), Err(ReportExecutionErrorV1::RowLimit));
}

#[test]
fn report_control_bytes_values_and_fuel_are_checked_before_admission() {
    for (charge, cap, reason) in [
        (
            QueryControl::charge_bytes
                as fn(&QueryControl, u64) -> Result<(), ReportExecutionErrorV1>,
            32 * 1024 * 1024,
            ReportExecutionErrorV1::ByteLimit,
        ),
        (
            QueryControl::charge_values
                as fn(&QueryControl, u64) -> Result<(), ReportExecutionErrorV1>,
            1_000_000,
            ReportExecutionErrorV1::ValueLimit,
        ),
        (
            QueryControl::charge_fuel
                as fn(&QueryControl, u64) -> Result<(), ReportExecutionErrorV1>,
            5_000_000,
            ReportExecutionErrorV1::FuelLimit,
        ),
    ] {
        let control = QueryControl::managed();
        charge(&control, cap).unwrap();
        let before = control.stats();
        assert_eq!(charge(&control, 1), Err(reason));
        let after = control.stats();
        assert_eq!(
            (after.bytes, after.values, after.fuel),
            (before.bytes, before.values, before.fuel)
        );
        assert_eq!(control.checkpoint(), Err(reason));
    }
}

#[test]
fn report_control_overflow_is_not_a_new_budget() {
    let control = QueryControl::managed();
    control.charge_bytes(1).unwrap();
    assert_eq!(
        control.charge_bytes(u64::MAX),
        Err(ReportExecutionErrorV1::ByteLimit)
    );
    assert_eq!(control.stats().bytes, 1);
}

#[test]
fn report_control_legacy_unlimited_does_not_inherit_managed_caps() {
    let control = QueryControl::unlimited();
    control.charge_rows(u64::MAX).unwrap();
    control.charge_bytes(u64::MAX).unwrap();
    control.charge_values(u64::MAX).unwrap();
    control.charge_fuel(u64::MAX).unwrap();
    assert_eq!(control.checkpoint(), Ok(()));
}

#[test]
fn report_control_queued_time_is_not_execution_time() {
    let control = QueryControl::managed();
    assert_eq!(control.stats().execution_ms, None);
    assert_eq!(control.stats().queue_wait_ms, None);
    control.begin_execution().unwrap();
    let before = control.stats().queue_wait_ms;
    control.begin_execution().unwrap();
    assert_eq!(control.stats().queue_wait_ms, before);
    assert!(control.stats().execution_ms.is_some());
}

#[test]
fn report_control_is_compatible_with_sql_callback_traits() {
    fn required_traits<T: Send + Sync + std::panic::RefUnwindSafe>() {}
    required_traits::<QueryControl>();
}

#[test]
fn report_control_feature_action_can_borrow_non_send_worker_state() {
    use aw_models::ReportFeatureAccessV1;
    use std::{cell::Cell, rc::Rc};
    struct Granted;
    impl ReportFeatureAccessV1 for Granted {
        fn with_access(
            &self,
            action: Box<dyn FnOnce() -> Result<(), ReportExecutionErrorV1> + '_>,
        ) -> Result<(), ReportExecutionErrorV1> {
            action()
        }
    }
    struct Denied;
    impl ReportFeatureAccessV1 for Denied {
        fn with_access(
            &self,
            _: Box<dyn FnOnce() -> Result<(), ReportExecutionErrorV1> + '_>,
        ) -> Result<(), ReportExecutionErrorV1> {
            Err(ReportExecutionErrorV1::EntitlementUnavailable)
        }
    }
    let calls = Rc::new(Cell::new(0));
    Granted
        .with_access(Box::new(|| {
            calls.set(calls.get() + 1);
            Ok(())
        }))
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(
        Denied.with_access(Box::new(|| {
            calls.set(calls.get() + 1);
            Ok(())
        })),
        Err(ReportExecutionErrorV1::EntitlementUnavailable)
    );
    assert_eq!(calls.get(), 1);
}
