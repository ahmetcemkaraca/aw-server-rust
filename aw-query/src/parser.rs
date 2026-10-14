#![allow(clippy::ptr_arg)]
#![allow(clippy::vec_init_then_push)]
use crate::ast::*;
use crate::lexer::Token::*;
use crate::lexer::*;
use aw_models::{QueryControl, QueryLimits, ReportExecutionErrorV1 as Error};
use plex::parser;
use std::{cell::RefCell, collections::HashMap};

type Expression = Result<Expr, Error>;
type Statements = Result<Vec<Expr>, Error>;
type ParsedProgram = Result<Program, Error>;
#[derive(Default)]
struct Construction {
    control: Option<QueryControl>,
    error: Option<Error>,
}
thread_local! {static CONSTRUCTION:RefCell<Construction>=RefCell::new(Construction::default());}
struct Scope(Option<Construction>);
impl Scope {
    fn new(control: &QueryControl) -> Self {
        Self(Some(CONSTRUCTION.with(|state| {
            state.replace(Construction {
                control: Some(control.clone()),
                error: None,
            })
        })))
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        CONSTRUCTION.with(|state| {
            state.replace(self.0.take().unwrap());
        });
    }
}
pub(crate) fn construction_error() -> Option<Error> {
    CONSTRUCTION.with(|state| state.borrow().error)
}
fn admit(depth: usize, bytes: usize, values: u64) -> Result<(), Error> {
    let control = CONSTRUCTION.with(|state| state.borrow().control.clone());
    let Some(control) = control else {
        return Ok(());
    };
    let result = (|| {
        control.checkpoint()?;
        if depth > QueryLimits::MANAGED.max_ast_depth {
            return Err(Error::ValueLimit);
        }
        control.charge_fuel(1)?;
        control.charge_values(values)?;
        control.charge_bytes(bytes as u64)
    })();
    if let Err(error) = result {
        CONSTRUCTION.with(|state| {
            state.borrow_mut().error.get_or_insert(error);
        });
    }
    result
}
fn admit_reduction<T>() -> Result<(), Error> {
    admit(
        0,
        std::mem::size_of::<T>() + std::mem::size_of::<Span>() + 3 * std::mem::size_of::<usize>(),
        1,
    )
}
fn make(span: Span, depth: usize, boxes: usize, node: impl FnOnce() -> Expr_) -> Expression {
    admit_reduction::<Expression>()?;
    admit(depth, boxes * std::mem::size_of::<Expr>(), 1 + boxes as u64)?;
    Ok(Expr {
        span,
        depth,
        node: node(),
    })
}
fn list_push(span: Span, list: Option<Expr>, item: Expr) -> Expression {
    let depth = list
        .as_ref()
        .map_or(item.depth + 1, |list| list.depth.max(item.depth + 1));
    make(span, depth, 0, || {
        let mut values = match list {
            Some(Expr {
                node: Expr_::List(values),
                ..
            }) => values,
            None => Vec::new(),
            _ => unreachable!(),
        };
        values.push(item);
        Expr_::List(values)
    })
}
fn dictionary(
    span: Span,
    prior: Option<Expr>,
    key: std::string::String,
    value: Expr,
) -> Expression {
    let depth = prior
        .as_ref()
        .map_or(value.depth + 1, |d| d.depth.max(value.depth + 1));
    admit(depth, std::mem::size_of::<(std::string::String, Expr)>(), 1)?;
    make(span, depth, 0, || {
        let mut entries = match prior {
            Some(Expr {
                node: Expr_::Dict(entries),
                ..
            }) => entries,
            None => HashMap::new(),
            _ => unreachable!(),
        };
        entries.insert(key, value);
        Expr_::Dict(entries)
    })
}
fn conditional(span: Span, left: Expr, right: Expr) -> Expression {
    let depth = left.depth.max(right.depth);
    let slots = match &right.node {
        Expr_::If(items) => items.len(),
        _ => unreachable!(),
    };
    admit(
        depth,
        slots * std::mem::size_of::<(Box<Expr>, Vec<Expr>)>(),
        slots as u64,
    )?;
    make(span, depth, 0, || {
        let Expr_::If(mut a) = left.node else {
            unreachable!()
        };
        let Expr_::If(mut b) = right.node else {
            unreachable!()
        };
        a.append(&mut b);
        Expr_::If(a)
    })
}
fn otherwise(span: Span, left: Expr, body: Vec<Expr>) -> Expression {
    let depth = left
        .depth
        .max(2)
        .max(body.iter().map(|e| e.depth + 1).max().unwrap_or(1));
    let condition = make(span, 1, 0, || Expr_::Bool(true))?;
    admit(depth, std::mem::size_of::<(Box<Expr>, Vec<Expr>)>(), 1)?;
    make(span, depth, 1, || {
        let Expr_::If(mut items) = left.node else {
            unreachable!()
        };
        items.push((Box::new(condition), body));
        Expr_::If(items)
    })
}
parser! {
    fn parse_(Token, Span);
    (a,b) {Span {lo:a.lo,hi:b.hi,line:a.line}}
    program: ParsedProgram {
        statements[s] => {let s=s?;admit_reduction::<ParsedProgram>()?;Ok(Program {stmts:s})}
    }
    statements: Statements {
        => {admit_reduction::<Statements>()?;Ok(Vec::new())},
        statements[s] statement[x] => {let mut s=s?;let x=x?;admit_reduction::<Statements>()?;admit(0,std::mem::size_of::<Expr>(),1)?;s.push(x);Ok(s)},
        statements[s] Semi => {admit_reduction::<Statements>()?;s}
    }
    statement: Expression {ifs[x]=>{admit_reduction::<Expression>()?;x},ret[x] Semi=>{admit_reduction::<Expression>()?;x}}
    ifs: Expression {_if[x]=>{admit_reduction::<Expression>()?;x},_elif[x]=>{admit_reduction::<Expression>()?;x},_else[x]=>{admit_reduction::<Expression>()?;x}}
    _cond_block: Expression {
        binop[condition] LBrace statements[body] RBrace => {
            let condition=condition?;let body=body?;
            let depth=(condition.depth+1).max(body.iter().map(|e|e.depth+1).max().unwrap_or(1));
            admit(depth,std::mem::size_of::<(Box<Expr>,Vec<Expr>)>(),1)?;
            make(span!(),depth,1,||Expr_::If(vec![(Box::new(condition),body)]))
        }
    }
    _if: Expression {If _cond_block[x]=>{admit_reduction::<Expression>()?;x}}
    _elif: Expression {
        _if[a] ElseIf _cond_block[b]=>conditional(span!(),a?,b?),
        _elif[a] ElseIf _cond_block[b]=>conditional(span!(),a?,b?)
    }
    _else: Expression {
        _if[a] Else LBrace statements[b] RBrace=>otherwise(span!(),a?,b?),
        _elif[a] Else LBrace statements[b] RBrace=>otherwise(span!(),a?,b?)
    }
    ret: Expression {
        Return assign[a]=>{let a=a?;make(span!(),a.depth+1,1,||Expr_::Return(Box::new(a)))},
        assign[x]=>{admit_reduction::<Expression>()?;x}
    }
    assign: Expression {
        Ident(name) Assign binop[value]=>{let value=value?;make(span!(),value.depth+1,1,||Expr_::Assign(name,Box::new(value)))},
        binop[x]=>{admit_reduction::<Expression>()?;x}
    }
    binop: Expression {
        binop[a] Plus func[b]=>{let a=a?;let b=b?;make(span!(),a.depth.max(b.depth)+1,2,||Expr_::Add(Box::new(a),Box::new(b)))},
        binop[a] Minus func[b]=>{let a=a?;let b=b?;make(span!(),a.depth.max(b.depth)+1,2,||Expr_::Sub(Box::new(a),Box::new(b)))},
        binop[a] Star func[b]=>{let a=a?;let b=b?;make(span!(),a.depth.max(b.depth)+1,2,||Expr_::Mul(Box::new(a),Box::new(b)))},
        binop[a] Slash func[b]=>{let a=a?;let b=b?;make(span!(),a.depth.max(b.depth)+1,2,||Expr_::Div(Box::new(a),Box::new(b)))},
        binop[a] Percent func[b]=>{let a=a?;let b=b?;make(span!(),a.depth.max(b.depth)+1,2,||Expr_::Mod(Box::new(a),Box::new(b)))},
        binop[a] Equals func[b]=>{let a=a?;let b=b?;make(span!(),a.depth.max(b.depth)+1,2,||Expr_::Equal(Box::new(a),Box::new(b)))},
        func[x]=>{admit_reduction::<Expression>()?;x}
    }
    func: Expression {
        Ident(name) LParen _inner_list[list] RParen=>{let list=list?;make(span!(),list.depth+1,1,||Expr_::Function(name,Box::new(list)))},
        Ident(name) LParen RParen=>{let list=make(span!(),1,0,||Expr_::List(Vec::new()))?;make(span!(),2,1,||Expr_::Function(name,Box::new(list)))},
        object[x]=>{admit_reduction::<Expression>()?;x}
    }
    object: Expression {
        LBrace dict[x] RBrace=>{admit_reduction::<Expression>()?;x},
        LBrace RBrace=>make(span!(),1,0,||Expr_::Dict(HashMap::new())),
        list[x]=>{admit_reduction::<Expression>()?;x}
    }
    list: Expression {
        LBracket _inner_list[x] RBracket=>{admit_reduction::<Expression>()?;x},
        LBracket RBracket=>make(span!(),1,0,||Expr_::List(Vec::new())),
        atom[x]=>{admit_reduction::<Expression>()?;x}
    }
    _inner_list: Expression {
        binop[x]=>{let x=x?;admit(x.depth+1,std::mem::size_of::<Expr>(),1)?;list_push(span!(),None,x)},
        _inner_list[list] Comma binop[item]=>{let list=list?;let item=item?;admit(list.depth.max(item.depth+1),std::mem::size_of::<Expr>(),1)?;list_push(span!(),Some(list),item)}
    }
    dict: Expression {
        String(key) Colon binop[value]=>dictionary(span!(),None,key,value?),
        dict[prior] Comma String(key) Colon binop[value]=>dictionary(span!(),Some(prior?),key,value?)
    }
    atom: Expression {
        Ident(name)=>make(span!(),1,0,||Expr_::Var(name)),
        Bool(value)=>make(span!(),1,0,||Expr_::Bool(value)),
        Number(value)=>make(span!(),1,0,||Expr_::Number(value)),
        String(value)=>make(span!(),1,0,||Expr_::String(value)),
        LParen binop[x] RParen=>{admit_reduction::<Expression>()?;x}
    }
}
pub type ParseError = (Option<(Token, Span)>, &'static str);
pub fn parse<I: Iterator<Item = (Token, Span)>>(i: I) -> Result<Program, ParseError> {
    parse_(i)?.map_err(|_| (None, "query construction failed"))
}
pub(crate) fn parse_controlled<I: Iterator<Item = (Token, Span)>>(
    i: I,
    control: &QueryControl,
) -> Result<Program, Error> {
    let _scope = Scope::new(control);
    let result = parse_(i);
    if let Some(error) = construction_error() {
        return Err(error);
    }
    result.map_err(|_| Error::InternalError)?
}
