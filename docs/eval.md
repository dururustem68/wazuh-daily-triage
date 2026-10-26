# Evaluation — measure the AI against days you reviewed yourself

`python -m app.eval` replays past windows (collection + AI analysis) and compares the findings with what a
human concluded. Nothing is stored; AI proposals are discarded. Use it to compare models, prompts and settings
with numbers instead of impressions.

```sh
python -m app.eval cases.yaml                          # current model
python -m app.eval cases.yaml --model other-model      # compare
python -m app.eval cases.yaml --repeat 3 --out res.json
kubectl -n wazuh-daily-triage exec -i deploy/wazuh-daily-triage -- python -m app.eval - < cases.yaml
```

A case is a window plus what *had* to be found (`expect`) and known noise that must *not* be reported as an
incident (`forbid`); see [`config/eval/demo.yaml`](../config/eval/demo.yaml) and the docstring of
[`app/eval.py`](../app/eval.py). Output per case: recall, missed items, noise violations, findings, steps,
tokens and time.

Limits: the knowledge base is today's, and non-time-bound tools (agents, vulnerabilities) answer with today's
state; the indexer must still hold the window.
