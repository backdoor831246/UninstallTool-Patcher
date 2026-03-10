# UninstallTool-Patcher
patches UninstallTool.exe to bypass the license check — overwrites IsRegistered() prologue with mov eax, 3 / ret so it always returns "fully licensed" without any IPC or server calls
