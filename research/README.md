# Data research

Exploratory SQL against lacuna's query API (read-only, the same path Sonder's
panels use). Each `.sql` file holds named blocks (`-- name: ...`); `ask.py` runs
them one at a time and prints the rows. `:now`, `:d1`, `:d7` and `:d30` are bound
to now and 1, 7 and 30 days ago.

```bash
docker run --rm --network lacuna-api -v ~/lacuna/research:/p:ro \
  -v ~/sonder/deploy/secrets/integrations/lacuna:/key:ro \
  python:3-alpine python -I /p/ask.py /p/01-overview.sql
```
