
rule CRxSocket_start
{
	meta:
		script = "Type.as CRxSocket"
		script = "Type.comment CRxSocket,\"通讯管理\""
		script = "Type.ad CRxSocket,\"inline bool is_socket_down() const {{ return (-1 == Socket); }};\""
		script = "Type.ad CRxSocket,\"void reset_counter();\""
	condition:
		true
}


//030 int Socket;
rule CRxSocket_Socket
{
	meta:
		script = "$result = byte:[@pattern + 0x13]"
		script = "Type.am CRxSocket,int,Socket,0,$result"
	strings:
		$pattern = { 83 ?? ?? 00 0F 85 [4] C7 ?? ?? 01 00 00 00 83 ?? ?? FF 0F 84 [4] 80 ?? ?? 01 }
	condition:
		#pattern == 1
}

//1a058 uint32_t last_move_item;
rule CRxSocket_last_send_time
{
	meta:
		script = "$result = [@pattern + 0x0d]"
		script = "Type.am CRxSocket,uint32_t,last_move_item,0,$result"
	strings:
		$pattern = { 1A [2] FF 15 [14] E8 03 00 00 }
	condition:
		#pattern == 1
}

//1a060 uint32_t last_life_drug;
rule CRxSocket_last_life_drug
{
	meta:
		script = "$result = [@pattern + 0x1c]"
		script = "Type.am CRxSocket,uint32_t,last_life_drug,0,$result"
	strings:
		$pattern = { 2A CB 9A 3B [5] 28 CB 9A 3B [5] FF 15 [6] 2B [7] 2C 01 00 00 }
	condition:
		#pattern == 1
}

//1a064 uint32_t last_energy_drug;
rule CRxSocket_last_energy_drug
{
	meta:
		script = "$result = [@pattern + 0x10]"
		script = "Type.am CRxSocket,uint32_t,last_energy_drug,0,$result"
	strings:
		$pattern = { 3A E3 14 3C [2] FF 15 [6] 2B [5] 81 ?? 2C 01 00 00 }
	condition:
		#pattern == 1
}

rule CRxSocket_end
{
	meta:
		script = "Type.print CRxSocket,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}