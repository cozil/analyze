
rule CRxSocket_start
{
	meta:
		script = "log \"struct CRxSocket {\""
	condition:
		true
}


//030 int Socket;
rule CRxSocket_Socket
{
	meta:
		script = "$result = byte:[@pattern + 0x02]"
		script = "log \"/*{p:$result}*/    int Socket;\""
	strings:
		$pattern = { 83 [2] FF [6] 80 [2] 01 [10] 40 9C 00 00 [6] 50 C3 00 00 }
	condition:
		#pattern == 1
}


//1a058 int last_move_item;
rule CRxSocket_last_send_time
{
	meta:
		script = "$result = [@pattern + 0x0d]"
		script = "log \"/*{p:$result}*/    int last_move_item;\""
	strings:
		$pattern = { 1A [2] FF 15 [14] E8 03 00 00 }
	condition:
		#pattern == 1
}

//1a060 int last_life_drug;
rule CRxSocket_last_life_drug
{
	meta:
		script = "$result = [@pattern + 0x1c]"
		script = "log \"/*{p:$result}*/    int last_life_drug;\""
	strings:
		$pattern = { 2A CB 9A 3B [5] 28 CB 9A 3B [5] FF 15 [6] 2B [7] 2C 01 00 00 }
	condition:
		#pattern == 1
}

//1a064 int last_energy_drug;
rule CRxSocket_last_energy_drug
{
	meta:
		script = "$result = [@pattern + 0x10]"
		script = "log \"/*{p:$result}*/    int last_energy_drug;\""
	strings:
		$pattern = { 3A E3 14 3C [2] FF 15 [6] 2B [5] 81 ?? 2C 01 00 00 }
	condition:
		#pattern == 1
}


rule CRxSocket_end
{
	meta:
		script = "log }"
		script = "log"
		script = "log"
	condition:
		true
}