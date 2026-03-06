# Metrics Formulas (Excel / Google Sheets)

Assume your data is in `results_template.csv`.

## Column meanings
- `ground_truth_vulnerable`: 1 or 0
- `predicted_positive`: 1 for warn/block, 0 for allow
- `tp`, `fp`, `tn`, `fn`: row-wise confusion indicators

## Row-wise formulas
Use these formulas per row:

- `tp`:
```excel
=IF(AND([@ground_truth_vulnerable]=1,[@predicted_positive]=1),1,0)
```

- `fp`:
```excel
=IF(AND([@ground_truth_vulnerable]=0,[@predicted_positive]=1),1,0)
```

- `tn`:
```excel
=IF(AND([@ground_truth_vulnerable]=0,[@predicted_positive]=0),1,0)
```

- `fn`:
```excel
=IF(AND([@ground_truth_vulnerable]=1,[@predicted_positive]=0),1,0)
```

## Aggregate totals
- `TP = SUM(tp_column)`
- `FP = SUM(fp_column)`
- `TN = SUM(tn_column)`
- `FN = SUM(fn_column)`

## Final metrics
- Precision:
```excel
=IF((TP+FP)=0,0,TP/(TP+FP))
```

- Recall:
```excel
=IF((TP+FN)=0,0,TP/(TP+FN))
```

- F1:
```excel
=IF((Precision+Recall)=0,0,2*Precision*Recall/(Precision+Recall))
```

- Accuracy:
```excel
=IF((TP+TN+FP+FN)=0,0,(TP+TN)/(TP+TN+FP+FN))
```

## Performance metrics
If `runtime_seconds` is a numeric column:
- Mean cold runtime: `AVERAGEIFS(runtime_seconds, experiment_type, "performance_cold")`
- Mean warm runtime: `AVERAGEIFS(runtime_seconds, experiment_type, "performance_warm")`
- Speedup (%):
```excel
=IF(mean_cold=0,0,(mean_cold-mean_warm)/mean_cold)
```

## Coverage metric
- Mean coverage baseline:
```excel
=AVERAGEIFS(coverage, experiment_type, "baseline")
```
- Mean coverage ablation:
```excel
=AVERAGEIFS(coverage, experiment_type, "ablation_no_oss")
```
