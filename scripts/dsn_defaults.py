import json
import os

from psycopg.conninfo import conninfo_to_dict

parsed = conninfo_to_dict(os.environ["ELDORADO_DATABASE_DSN"])
print(json.dumps({k: str(parsed.get(k) or "") for k in ("host", "port", "dbname")}))