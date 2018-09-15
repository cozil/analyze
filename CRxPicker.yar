rule CRxPicker_start
{
	meta:
		script = "log \"struct CRxPicker {\""
	condition:
		true
}


//228 CRxStuff  * a_stuff;
rule CRxPicker_a_stuff
{
	meta:
		script = "$result = [@pattern + 0x2e]"
		script = "log \"/*{p:$result}*/    CRxStuff  * a_stuff;\""
	strings:
		$pattern = { C7 85 [4] 0B 00 00 00 80 3D [4] 00 [6] A1 [4] 89 B5 [4] C7 85 [4] FF FF FF FF 39 B0 }
	condition:
		#pattern == 1
}

//230 int a_enable;
rule CRxPicker_a_enable
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"/*{p:$result}*/    int a_enable;\""
	strings:
		$pattern = { 38 81 [6] E8 [4] A1 [4] ?? FF FF 00 00 [6] ?? 0F 27 00 00 }
	condition:
		#pattern == 1
}



rule CRxPicker_end
{
	meta:
		script = "log }"
		script = "log"
		script = "log"
	condition:
		true
}