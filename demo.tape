Output demo.gif
Set FontSize 18
Set Width 1200
Set Height 700
Set Theme "Dracula"

Type "aiguard init"
Sleep 500ms
Enter
Sleep 3s
Type "aiguard doctor"
Enter
Sleep 3s
Type "aiguard hook claude-code pre"
Sleep 500ms
Enter
Sleep 1s
Type '{"hook_event_name":"PreToolUse","session_id":"demo","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}'
Enter
Sleep 2s
Type "aiguard replay --last"
Enter
Sleep 4s
