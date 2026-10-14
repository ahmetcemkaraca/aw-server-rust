use std::collections::HashMap;

use crate::functions;

use aw_datastore::Datastore;
use aw_models::TimeInterval;

use crate::ast::*;
use crate::DataType;
use crate::QueryError;

pub type VarEnv = HashMap<String, DataType>;

fn init_env(ti: &TimeInterval) -> VarEnv {
    let mut env = HashMap::new();
    env.insert("TIMEINTERVAL".to_string(), DataType::String(ti.to_string()));
    functions::fill_env(&mut env);
    env
}

pub fn interpret_prog(
    p: Program,
    ti: &TimeInterval,
    ds: &Datastore,
) -> Result<DataType, QueryError> {
    let mut env = init_env(ti);
    for expr in p.stmts {
        interpret_expr(&mut env, ds, expr)?;
    }
    match env.remove("RETURN") {
        Some(ret) => Ok(ret),
        None => Err(QueryError::EmptyQuery()),
    }
}

fn interpret_expr(
    env: &mut HashMap<String, DataType>,
    ds: &Datastore,
    expr: Expr,
) -> Result<DataType, QueryError> {
    use crate::ast::Expr_::*;
    match expr.node {
        Add(a, b) => {
            let a_res = interpret_expr(env, ds, *a)?;
            let b_res = interpret_expr(env, ds, *b)?;
            let res = match a_res {
                DataType::Number(n1) => match b_res {
                    DataType::Number(n2) => DataType::Number(n1 + n2),
                    _ => {
                        return Err(QueryError::InvalidType(
                            "Cannot use + on something that is not a number with a number!"
                                .to_string(),
                        ))
                    }
                },
                DataType::List(mut l1) => match b_res {
                    DataType::List(mut l2) => {
                        l1.append(&mut l2);
                        DataType::List(l1)
                    }
                    _ => {
                        return Err(QueryError::InvalidType(
                            "Cannot use + on something that is not a list with a list!".to_string(),
                        ))
                    }
                },
                DataType::String(s1) => match b_res {
                    DataType::String(s2) => {
                        let mut new_string = s1;
                        new_string.push_str(&s2);
                        DataType::String(new_string)
                    }
                    _ => {
                        return Err(QueryError::InvalidType(
                            "Cannot use + on something that is not a list with a list!".to_string(),
                        ))
                    }
                },
                _ => {
                    return Err(QueryError::InvalidType(
                        "Cannot use + on something that is not a number, list or string!"
                            .to_string(),
                    ))
                }
            };
            Ok(res)
        }
        Sub(a, b) => {
            let a_res = interpret_expr(env, ds, *a)?;
            let b_res = interpret_expr(env, ds, *b)?;
            let a_num = match a_res {
                DataType::Number(n) => n,
                _ => {
                    return Err(QueryError::InvalidType(
                        "Cannot sub something that is not a number!".to_string(),
                    ))
                }
            };
            let b_num = match b_res {
                DataType::Number(n) => n,
                _ => {
                    return Err(QueryError::InvalidType(
                        "Cannot sub something that is not a number!".to_string(),
                    ))
                }
            };
            Ok(DataType::Number(a_num - b_num))
        }
        Mul(a, b) => {
            let a_res = interpret_expr(env, ds, *a)?;
            let b_res = interpret_expr(env, ds, *b)?;
            let a_num = match a_res {
                DataType::Number(n) => n,
                _ => {
                    return Err(QueryError::InvalidType(
                        "Cannot sub something that is not a number!".to_string(),
                    ))
                }
            };
            let b_num = match b_res {
                DataType::Number(n) => n,
                _ => {
                    return Err(QueryError::InvalidType(
                        "Cannot sub something that is not a number!".to_string(),
                    ))
                }
            };
            Ok(DataType::Number(a_num * b_num))
        }
        Div(a, b) => {
            let a_res = interpret_expr(env, ds, *a)?;
            let b_res = interpret_expr(env, ds, *b)?;
            let a_num = match a_res {
                DataType::Number(n) => n,
                _ => {
                    return Err(QueryError::InvalidType(
                        "Cannot sub something that is not a number!".to_string(),
                    ))
                }
            };
            let b_num = match b_res {
                DataType::Number(n) => n,
                _ => {
                    return Err(QueryError::InvalidType(
                        "Cannot sub something that is not a number!".to_string(),
                    ))
                }
            };
            if b_num == 0.0 {
                return Err(QueryError::MathError(
                    "Tried to divide by zero!".to_string(),
                ));
            }
            Ok(DataType::Number(a_num / b_num))
        }
        Mod(a, b) => {
            let a_res = interpret_expr(env, ds, *a)?;
            let b_res = interpret_expr(env, ds, *b)?;
            let a_num = match a_res {
                DataType::Number(n) => n,
                _ => {
                    return Err(QueryError::InvalidType(
                        "Cannot sub something that is not a number!".to_string(),
                    ))
                }
            };
            let b_num = match b_res {
                DataType::Number(n) => n,
                _ => {
                    return Err(QueryError::InvalidType(
                        "Cannot sub something that is not a number!".to_string(),
                    ))
                }
            };
            Ok(DataType::Number(a_num % b_num))
        }
        Equal(lhs, rhs) => {
            let lhs_res = interpret_expr(env, ds, *lhs)?;
            let rhs_res = interpret_expr(env, ds, *rhs)?;
            Ok(DataType::Bool(lhs_res.query_eq(&rhs_res)?))
        }
        Assign(var, b) => {
            let val = interpret_expr(env, ds, *b)?;
            env.insert(var, val);
            Ok(DataType::None())
        }
        // This clone is the one necessary copy per variable reference: the env
        // must retain the value since it may be referenced again, while
        // function arguments and transforms need owned events.
        Var(var) => match env.get(&var) {
            Some(v) => Ok(v.clone()),
            None => Err(QueryError::VariableNotDefined(var.to_string())),
        },
        Bool(lit) => Ok(DataType::Bool(lit)),
        Number(lit) => Ok(DataType::Number(lit)),
        String(litstr) => Ok(DataType::String(litstr)),
        Return(e) => {
            let val = interpret_expr(env, ds, *e)?;
            // TODO: Once RETURN is deprecated we can fix this
            env.insert("RETURN".to_string(), val);
            Ok(DataType::None())
        }
        If(ifs) => {
            for (cond, block) in ifs {
                let c = interpret_expr(env, ds, *cond)?;
                if c.query_eq(&DataType::Bool(true))? {
                    for expr in block {
                        interpret_expr(env, ds, expr)?;
                    }
                    break;
                }
            }
            Ok(DataType::None())
        }
        Function(fname, e) => {
            let args = match interpret_expr(env, ds, *e)? {
                DataType::List(l) => l,
                _ => unreachable!(),
            };
            let var = match env.get(&fname[..]) {
                Some(v) => v,
                None => return Err(QueryError::VariableNotDefined(fname.clone())),
            };
            let (_name, fun) = match var {
                DataType::Function(name, fun) => (name, fun),
                _data => return Err(QueryError::InvalidType(fname.to_string())),
            };
            fun(args, env, ds)
        }
        List(list) => {
            let mut l = Vec::new();
            for entry in list {
                let res = interpret_expr(env, ds, entry)?;
                l.push(res);
            }
            Ok(DataType::List(l))
        }
        Dict(d) => {
            let mut dict = HashMap::new();
            for (key, val_uninterpreted) in d {
                let val = interpret_expr(env, ds, val_uninterpreted)?;
                dict.insert(key, val);
            }
            Ok(DataType::Dict(dict))
        }
    }
}

pub(crate) fn interpret_controlled(
    p: Program,
    ti: &TimeInterval,
    source: &crate::FrozenQuerySource,
    control: &aw_models::QueryControl,
) -> Result<DataType, aw_models::ReportExecutionErrorV1> {
    use aw_models::ReportExecutionErrorV1 as Error;
    control.charge_bytes(
        (128 + "TIMEINTERVAL".len() + std::mem::size_of::<(std::string::String, DataType)>())
            as u64,
    )?;
    control.charge_values(1)?;
    let mut env = HashMap::new();
    let interval = ti.to_string();
    env.insert("TIMEINTERVAL".into(), DataType::String(interval));
    crate::functions::fill_controlled_env(&mut env, control)?;
    for expr in p.stmts {
        controlled_expr(&mut env, ti, source, control, expr)?;
    }
    let result = env.remove("RETURN").ok_or(Error::InternalError)?;
    result.validate_controlled(control)?;
    Ok(result)
}
fn controlled_expr(
    env: &mut VarEnv,
    ti: &TimeInterval,
    source: &crate::FrozenQuerySource,
    control: &aw_models::QueryControl,
    expr: Expr,
) -> Result<DataType, aw_models::ReportExecutionErrorV1> {
    use crate::ast::Expr_::*;
    use aw_models::ReportExecutionErrorV1 as Error;
    control.charge_fuel(1)?;
    let operator = match &expr.node {
        Add(_, _) => 0,
        Sub(_, _) => 1,
        Mul(_, _) => 2,
        Div(_, _) => 3,
        Mod(_, _) => 4,
        Equal(_, _) => 5,
        _ => 255,
    };
    match expr.node {
        Add(a, b) | Sub(a, b) | Mul(a, b) | Div(a, b) | Mod(a, b) | Equal(a, b) => {
            let left = controlled_expr(env, ti, source, control, *a)?;
            let right = controlled_expr(env, ti, source, control, *b)?;
            match (operator, left, right) {
                (0, DataType::List(mut a), DataType::List(mut b)) => {
                    control.charge_values(b.len() as u64)?;
                    control.charge_bytes(
                        ((a.len() + b.len()) * std::mem::size_of::<DataType>()) as u64,
                    )?;
                    a.append(&mut b);
                    Ok(DataType::List(a))
                }
                (0, DataType::String(mut a), DataType::String(b)) => {
                    control.charge_bytes((a.len() + b.len()) as u64)?;
                    a.push_str(&b);
                    Ok(DataType::String(a))
                }
                (5, a, b) => {
                    a.validate_controlled(control)?;
                    b.validate_controlled(control)?;
                    let equal = match (&a, &b) {
                        (DataType::None(), DataType::None()) => false,
                        (DataType::Bool(_), DataType::Bool(_))
                        | (DataType::Number(_), DataType::Number(_))
                        | (DataType::String(_), DataType::String(_))
                        | (DataType::List(_), DataType::List(_))
                        | (DataType::Dict(_), DataType::Dict(_))
                        | (DataType::Event(_), DataType::Event(_)) => a == b,
                        _ => return Err(Error::InternalError),
                    };
                    control.checkpoint()?;
                    Ok(DataType::Bool(equal))
                }
                (op, DataType::Number(a), DataType::Number(b)) => {
                    let n = match op {
                        0 => a + b,
                        1 => a - b,
                        2 => a * b,
                        3 => a / b,
                        4 => a % b,
                        _ => return Err(Error::InternalError),
                    };
                    if n.is_finite() {
                        Ok(DataType::Number(n))
                    } else {
                        Err(Error::InternalError)
                    }
                }
                _ => Err(Error::InternalError),
            }
        }
        Var(name) => {
            let value = env.get(&name).ok_or(Error::InternalError)?;
            value.charge_copy(control)?;
            Ok(value.clone())
        }
        Assign(name, value) => {
            let value = controlled_expr(env, ti, source, control, *value)?;
            control.charge_values(1)?;
            control.charge_bytes(
                (name.len() + std::mem::size_of::<(std::string::String, DataType)>()) as u64,
            )?;
            env.insert(name, value);
            Ok(DataType::None())
        }
        Return(value) => {
            let value = controlled_expr(env, ti, source, control, *value)?;
            control.charge_values(1)?;
            control.charge_bytes(
                ("RETURN".len() + std::mem::size_of::<(std::string::String, DataType)>()) as u64,
            )?;
            env.insert("RETURN".into(), value);
            Ok(DataType::None())
        }
        Function(name, args) => {
            let canonical = match env.get(&name) {
                Some(DataType::Function(name, _)) => name.as_str(),
                _ => return Err(Error::InternalError),
            };
            control.charge_bytes(canonical.len() as u64)?;
            let canonical = canonical.to_owned();
            let args = controlled_expr(env, ti, source, control, *args)?.controlled_list()?;
            crate::functions::dispatch_controlled(&canonical, args, env, ti, source, control)
        }
        If(branches) => {
            for (condition, body) in branches {
                let condition = controlled_expr(env, ti, source, control, *condition)?;
                let DataType::Bool(truth) = condition else {
                    return Err(Error::InternalError);
                };
                if truth {
                    for item in body {
                        controlled_expr(env, ti, source, control, item)?;
                    }
                    break;
                }
            }
            Ok(DataType::None())
        }
        Bool(value) => Ok(DataType::Bool(value)),
        Number(value) => Ok(DataType::Number(value)),
        String(value) => Ok(DataType::String(value)),
        List(items) => {
            let mut output = Vec::new();
            for item in items {
                control.charge_values(1)?;
                control.charge_bytes(std::mem::size_of::<DataType>() as u64)?;
                output.push(controlled_expr(env, ti, source, control, item)?);
            }
            Ok(DataType::List(output))
        }
        Dict(items) => {
            let mut output = HashMap::new();
            for (key, item) in items {
                control.charge_values(1)?;
                control
                    .charge_bytes(std::mem::size_of::<(std::string::String, DataType)>() as u64)?;
                output.insert(key, controlled_expr(env, ti, source, control, item)?);
            }
            Ok(DataType::Dict(output))
        }
    }
}
