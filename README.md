# 样本监管链服务

这是赛事反兴奋剂样本监管链服务的 Python 起点。`app/samples.py` 目前只保留样本条码和容器信息，交接、封条、拆分和审计流程需要后续建设。

## 运行

```bash
python -m unittest discover -s tests -v
```

## 目录

- `app/samples.py`：样本基础对象
- `tests/`：基础行为测试

