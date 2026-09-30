# SDKs

The Node and Python SDKs write sanitized JSON Lines records to `.faultnest/requests.jsonl` locally. They make no network calls and do not read environment values. Feed a selected record/file to `faultnest capture --request` after reviewing it.
