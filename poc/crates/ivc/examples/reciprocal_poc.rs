use ark_std::error::Error;
use sonobe_ivc::compilers::cyclefold::adapters::reciprocal_bench::{
    BenchmarkSnapshotRow, benchmark_snapshot_rows,
};

fn main() -> Result<(), Box<dyn Error>> {
    let [stock_row, naive_row, reciprocal_row] = benchmark_snapshot_rows()?;
    println!("{}", BenchmarkSnapshotRow::csv_header());
    println!("{}", stock_row.csv_row());
    println!("{}", naive_row.csv_row());
    println!("{}", reciprocal_row.csv_row());

    Ok(())
}
