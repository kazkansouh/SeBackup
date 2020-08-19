# Backup and Restore

Repository contains two simple programs that exercise the
`SeBackupPrivilege` and `SeRestorePrivilege` on file
operations. I.e. it calls `CreateFile` with
[`FILE_FLAG_BACKUP_SEMANTICS`][createfile].


The programs are as follows:

* `backup`: if provided with a file, will cat it to the terminal, else
  if directory will list its contents (by enabling the
  `SeBackupPrivilege` and calling `cmd /c dir ...`).
* `restore` reads from `stdin` and write to the specified file.


Developed to compile with MinGW (see compilation instructions in the
files), but should also work fine in Visual Studio.


Copyright 2020, Karim Kanso. All rights reserved. Licensed under GPLv3.

[createfile]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea

