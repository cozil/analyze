rule CRxGroundStuff_start
{
	meta:
		script = "Type.as CRxGroundStuff"
		script = "Type.aanc CRxGroundStuff,CRxObject"
	condition:
		true
}

//048 POINT3D s_pos;
rule CRxGroundStuff_s_pos
{
	meta:
		script = "$result = byte:[@pattern + 0x04]"
		script = "Type.am CRxGroundStuff,POINT3D,s_pos,0,$result"
		script = "Type.mcomment CRxGroundStuff,s_pos,\"地上物品坐标\""
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
		script = "Type.am CRxGroundStuff,int,s_code1,0,$result"
		script = "$result = byte:[@pattern + 0x05]"
		script = "Type.am CRxGroundStuff,int,s_code2,0,$result"
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
		script = "Type.am CRxGroundStuff,int,s_code,0,$result"
		script = "Type.am CRxGroundStuff,int,s_codeEx,0,$result+4"
		script = "Type.mcomment CRxGroundStuff,s_code,\"物品代码\""
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
		script = "Type.am CRxGroundStuff,char,s_name,0x3c,$result"
		script = "Type.mcomment CRxGroundStuff,s_name,\"地上物品名称\""
	strings:
		$pattern = { 8D BB [4] 6A 40 57 E8 [4] 83 C4 20 81 7E ?? 00 94 35 77 }
	condition:
		#pattern == 1
}


rule CRxGroundStuff_end
{
	meta:
		script = "Type.print CRxGroundStuff,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}