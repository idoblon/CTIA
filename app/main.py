"""
Entry point for CTIA project.
Usage:
python -m app.main run_all
python -m app.main fetch
python -m app.main normalize
python -m app.main ingest
"""
import sys
from app.core.threat_feeds import fetch_all_feeds, RAW_DIR
from app.core.normalizer import normalize_all_feeds
from app.db.database import initialize_database, ingest_normalized




def run_all():
    fetch_all_feeds()
    normalize_all_feeds()
    initialize_database()
    ingest_normalized()




def main(argv=None):
    argv = argv or sys.argv[1:]
    if not argv:
        print('Usage: run_all | fetch | normalize | ingest')
        return
    cmd = argv[0]
    if cmd == 'run_all':
        run_all()
    elif cmd == 'fetch':
        fetch_all_feeds()
    elif cmd == 'normalize':
        normalize_all_feeds()
    elif cmd == 'ingest':
        initialize_database(); ingest_normalized()
    else:
        print('Unknown command')




if __name__ == '__main__':
    main()