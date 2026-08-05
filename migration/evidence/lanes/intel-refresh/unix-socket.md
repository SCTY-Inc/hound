# intel-refresh: unix-socket evidence

The c782f49 cutover routes acquisition through the local houndd Unix socket.
The current main repair at 7de92fa7ed8698ecbd5545e2cb79ba7642bee008 consumes
the canonical Hound URL record returned by that path. The lane holds no
provider credentials or direct provider client.
