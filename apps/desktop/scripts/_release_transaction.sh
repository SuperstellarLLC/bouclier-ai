# Transaction helpers for release.sh's tracked metadata edits.
# Source this file; do not execute it directly.

RELEASE_TRANSACTION_BACKUP_DIR=""
RELEASE_TRANSACTION_COMMITTED=false
RELEASE_TRANSACTION_PATHS=()

release_transaction_begin() {
  if [ "$#" -eq 0 ]; then
    echo "ERROR: release transaction needs at least one metadata path." >&2
    return 1
  fi
  if [ -n "$RELEASE_TRANSACTION_BACKUP_DIR" ]; then
    echo "ERROR: release transaction is already active." >&2
    return 1
  fi

  RELEASE_TRANSACTION_BACKUP_DIR=$(mktemp -d /tmp/bouclier-release.XXXXXX) || {
    echo "ERROR: could not create the release metadata backup." >&2
    return 1
  }
  RELEASE_TRANSACTION_PATHS=("$@")
  RELEASE_TRANSACTION_COMMITTED=false

  local index path
  for index in "${!RELEASE_TRANSACTION_PATHS[@]}"; do
    path="${RELEASE_TRANSACTION_PATHS[$index]}"
    if [ -f "$path" ]; then
      if ! cp -p "$path" "$RELEASE_TRANSACTION_BACKUP_DIR/$index"; then
        echo "ERROR: could not back up release metadata: $path" >&2
        rm -rf "$RELEASE_TRANSACTION_BACKUP_DIR"
        RELEASE_TRANSACTION_BACKUP_DIR=""
        RELEASE_TRANSACTION_PATHS=()
        return 1
      fi
    elif [ ! -e "$path" ]; then
      # The appcast normally exists, but record absence so a newly created file
      # is removed on rollback instead of surviving a failed release.
      : > "$RELEASE_TRANSACTION_BACKUP_DIR/$index.missing"
    else
      echo "ERROR: release metadata is not a regular file: $path" >&2
      rm -rf "$RELEASE_TRANSACTION_BACKUP_DIR"
      RELEASE_TRANSACTION_BACKUP_DIR=""
      RELEASE_TRANSACTION_PATHS=()
      return 1
    fi
  done
}

release_transaction_commit() {
  if [ -z "$RELEASE_TRANSACTION_BACKUP_DIR" ]; then
    echo "ERROR: no active release transaction to commit." >&2
    return 1
  fi
  RELEASE_TRANSACTION_COMMITTED=true
}

release_transaction_finish() {
  local original_status="${1:-0}"
  local final_status="$original_status"
  local index path

  # This function is normally called from EXIT. Disable errexit so one failed
  # restore cannot prevent the remaining tracked files from being restored.
  set +e
  if [ -n "$RELEASE_TRANSACTION_BACKUP_DIR" ]; then
    if [ "$RELEASE_TRANSACTION_COMMITTED" != true ]; then
      echo ""
      echo "↩ Restoring tracked release metadata after the failed release..." >&2
      for index in "${!RELEASE_TRANSACTION_PATHS[@]}"; do
        path="${RELEASE_TRANSACTION_PATHS[$index]}"
        if [ -f "$RELEASE_TRANSACTION_BACKUP_DIR/$index.missing" ]; then
          if ! rm -f "$path"; then
            echo "ERROR: could not remove newly created metadata: $path" >&2
            final_status=1
          fi
        elif ! cp -p "$RELEASE_TRANSACTION_BACKUP_DIR/$index" "$path"; then
          echo "ERROR: could not restore release metadata: $path" >&2
          final_status=1
        fi
      done
    fi

    if ! rm -rf "$RELEASE_TRANSACTION_BACKUP_DIR"; then
      echo "WARNING: could not remove temporary release backup: $RELEASE_TRANSACTION_BACKUP_DIR" >&2
    fi
  fi

  RELEASE_TRANSACTION_BACKUP_DIR=""
  RELEASE_TRANSACTION_PATHS=()
  RELEASE_TRANSACTION_COMMITTED=false
  return "$final_status"
}
