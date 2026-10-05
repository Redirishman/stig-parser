"""Size limits shared by the upload entry points and the archive reader.

One definition: the Flask app and the Lambda stages refuse a loose upload
larger than MAX_UPLOAD_BYTES, and the archive reader refuses a member larger
than that, so a few KB of ZIP cannot buy a file the upload limit would refuse.
This module imports nothing, so any layer may depend on it.
"""

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # per file
