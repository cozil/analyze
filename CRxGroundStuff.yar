rule CRxGroundStuff_start
{
	meta:
		script = "log \"struct CRxGroundStuff {\""
	condition:
		true
}

//048 POINT3D s_pos;
rule CRxGroundStuff_s_pos
{
	meta:
		script = "$result = byte:[@pattern + 0x04]"
		script = "log \"//地上物品坐标\""
		script = "log \"/*{p:$result}*/    POINT3D s_pos;\""
	strings:
		$pattern = { 6A 00 D9 5B ?? 6A 1C [47] 6A 00 6A 1B 50 FF D2 }
	condition:
		#pattern == 1
}

//06c int s_code1;
//070 int s_code2;
rule CRxGroundStuff_s_code1
{
	meta:
		script = "$result = byte:[@pattern + 0x02]"
		script = "log \"/*{p:$result}*/    int s_code1;\""
		script = "$result = byte:[@pattern + 0x05]"
		script = "log \"/*{p:$result}*/    int s_code2;\""
	strings:
		$pattern = { 8B 4E ?? 8B 56 ?? 83 C4 0C 6A 0E 8D 85 [4] 89 8D [4] 8B 0D [4] 50 C7 85 [4] 0B 00 08 00 }
	condition:
		#pattern == 1
}

//078 int s_code;
rule CRxGroundStuff_s_code
{
	meta:
		script = "$result = byte:[@pattern + 0x02]"
		script = "log \"//物品代码\""
		script = "log \"/*{p:$result}*/    int s_code;\""
		script = "log \"/*{p:$result+4}*/    int s_codeEx;\""
	strings:
		$pattern = { 81 79 ?? 5B CA 9A 3B [2] 83 79 ?? 00 [2] 66 83 3D [4] 06 }
	condition:
		#pattern == 1
}

//94 char s_name[0x3c];
rule CRxGroundStuff_s_name
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"///地上物品名称\""
		script = "log \"/*{p:$result}*/    char s_name[0x3c];\""
	strings:
		$pattern = { 8D BB [4] 6A 40 57 E8 [4] 83 C4 20 81 7E ?? 00 94 35 77 }
	condition:
		#pattern == 1
}


rule CRxGroundStuff_end
{
	meta:
		script = "log }"
		script = "log"
		script = "log"
	condition:
		true
}