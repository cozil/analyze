
rule BtnTest
{
	meta:
		script = "$result = @pattern + 0x13"
		script = "lblset $result, BtnTest"
		script = "log \"BtnTest=0x{$result}\""
	strings:
		$pattern = { 8B 86 54 02 00 00 8B 11 8B 52 04 6A 00 50 68 F4 03 00 00 FF D2 5F 5B C6 86 28 02 00 00 00 }
	condition:
		#pattern == 1
}

rule ResponseAttack
{
	meta:
		script = "lblset @pattern, ResponseAttack"
		script = "log \"ResponseAttack=0x{@pattern}\""
	strings:
		$pattern = { 55 8B EC 6A FF [45] 8B 7D 08 8D 77 06 B8 1F 27 00 00 33 DB 89 BD 98 D2 FF FF 66 39 46 02 }
	condition:
		#pattern == 1
}

rule ResponseQdAttack
{
	meta:
		script = "lblset @pattern, ResponseQdAttack"
		script = "log \"ResponseQdAttack=0x{@pattern}\""
	strings:
		$pattern = { 55 8B EC 81 [15] 8B 45 08 0F B7 08 53 56 57 89 85 50 FF FF FF 8D 70 06 }
	condition:
		#pattern == 1
}

rule HR_CPU
{
	meta:
		script = "log \"HR_CPU=0x{@pattern+0x10}\""
		//script = "lblset @pattern+0x10, HR_CPU"
	strings:
		$pattern = { D9 9E [4] E8 [4] E8 [4] E8 [4] 53 68 FF 00 00 00 6A 08 }
	condition:
		#pattern == 1	
}

rule NP_MAP
{
	meta:
		script = "$result = [@pattern + 0x04]"
		script = "lblset $result, CurMapID2"
		script = "log \"NP_MAP=0x{$result}\""
	strings:
		$pattern = { 83 C4 04 A1 [4] 3D 8D 23 00 00 74 ?? 3D 29 23 00 00 74 ?? 3D F1 23 00 00 }
	condition:
		#pattern == 1	
}


rule NP_BASE
{
	meta:
		script = "$result = [@pattern + 0x0A]"
		script = "lblset $result, RoleInfo"
		script = "log \"NP_BAS=0x{$result}\""
	strings:
		$pattern = { 8A 4E 06 88 48 2C 8D 78 04 B9 }
	condition:
		#pattern == 1	
}

rule NP_SVT
{
	meta:
		script = "$result = [@pattern + 0x3c]"
		script = "lblset $result, SelServerTitle"
		script = "log \"NP_SVT=0x{$result}\""
		script = "$result = [@pattern + 0x06]"
		script = "lblset $result, SelServerIndex"
		script = "log \"NP_SSI=0x{$result}\""
		script = "$result = [@pattern + 0x15]"
		script = "lblset $result, SelLineIndex"
		script = "log \"NP_SLI=0x{$result}\""
	
	strings:
		$pattern = { 57 6A 01 6A 04 68 [4] E8 [4] 57 6A 01 6A 04 68 [4] E8 [4] 83 C4 20 BE [4] 8D 49 00 57 6A 01 6A 50 56 E8 [4] 83 C6 50 83 C4 10 81 FE }
	condition:
		#pattern == 1			
}

rule NP_STG
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "lblset $result, GameStage"
		script = "log \"NP_STG=0x{$result}\""
	strings:
		$pattern = { 3B 05 [4] 0F 84 [4] 8B 4F ?? A3 [4] 3B CE 74 ?? 8B 01 8B 10 6A 01 FF D2 89 77 ?? 8B 47 ?? 83 F8 01 }
	condition:
		#pattern == 1	
}

rule NP_SRI
{
	meta:
		script = "lblset @pattern, SaveToolbar"
		script = "log \"NF_CSC=0x{@pattern}\""
		script = "$result = [@pattern + 0x25]"
		script = "lblset $result, SelRoleIndex"
		script = "log \"NP_SRI=0x{$result}\""
	strings:
		$pattern = { 55 8B EC 83 [31] 8B 0D [4] 51 68 [4] 68 [4] 8D 55 AC 6A 50 52 E8 [4] 83 C4 20 B8 [4] 38 58 FE }
	condition:
		#pattern == 1	
}

rule HR_GLR
{
	meta:
		script = "$result = @pattern + 0x2b + [@pattern + 0x27]"
		script = "log \"HR_GLR=0x{@pattern + 0x26}\""
		script = "lblset $result, GameLoginResponse"
		//script = "lblset @pattern + 0x26, HR_GLR"
	strings:
		$pattern = { 74 ?? 8D 49 00 83 BE [4] 00 74 25 83 BE [4] 00 8B 47 ?? 8B 3F 74 ?? 8B 48 ?? 8B 50 ?? 51 52 8B CE E8 }
	condition:
		#pattern == 1	
}


rule NF_GSS
{
	meta:
		script = "log \"NF_GSS=0x{@pattern}\""
		script = "lblset @pattern, Send_GetServerState"
	strings:
		$pattern = { 56 57 6A 04 8B F9 E8 [4] 83 C4 04 8B F0 6A 01 56 6A 04 8B CF C7 06 16 80 00 00 }
	condition:
		#pattern == 1	
}


rule HF_LFE
{
	meta:
		script = "log \"HF_LFE=0x{@pattern+0x05},eb\""
		script = "lblset @pattern+0x05, HF_LFE"
	strings:
		$pattern = { DF E0 F6 C4 41 75 0C [6] 00 00 00 00 [8] 81 3D [4] 29 A0 00 00 }
	condition:
		#pattern == 1	
}

rule HF_DIT
{
	meta:
		script = "log \"HF_DIT=0x{@pattern},c3\""
		//script = "lblset @pattern, HF_DIT"
	strings:
		$pattern = { 55 8B EC 51 [31] 56 68 [4] 68 00 01 00 00 50 8B 42 24 88 4D FF FF D0 8B F0 81 FE 1E 00 07 80 }
	condition:
		#pattern == 1	
}

rule NF_CTD
{
	meta:
		script = "log \"NF_CTD=0x{@pattern}\""
		script = "lblset @pattern, CopyTaskData"
	strings:
		$pattern = { 55 8B EC 53 [27] 8A 57 20 88 56 20 8A 47 21 8B CF 88 46 21 8D 46 22 }
	condition:
		#pattern == 1	
}


rule NP_TSK
{
	meta:
		script = "$result = [@pattern + 0x27]"
		script = "log \"NP_TSK=0x{$result}\""
		script = "lblset $result, TaskRawData"
	strings:
		$pattern = { 8D 49 00 8B 38 89 39 8B 78 04 89 79 04 83 C0 08 83 C1 08 3B C2 75 ?? 89 4E 04 8D 8D B8 FD FF FF E8 [4] 8B 3D }
	condition:
		#pattern == 1	
}

rule NP_NPC
{
	meta:
		script = "$result = [@pattern + 0x10]"
		script = "log \"NP_NPC=0x{$result}\""
		script = "lblset $result, NpcRawData"
		script = "$result = [@pattern + 0x1f]"
		script = "lblset $result, NpcRawDataEnd"
	strings:
		$pattern = { BE DE 27 00 00 [3] 75 [6] B8 [6] 74 ?? 05 [4] 41 3D }
	condition:
		#pattern == 1	
}

rule HF_WPN
{
	meta:
		script = "log \"HF_WPN=0x{@pattern + 0x0D},eb\""
		//script = "lblset @pattern + 0x0D, HF_WPN"
	strings:
		$pattern = { 8B 81 40 04 00 00 83 B8 A0 0D 00 00 02 74 ?? 8B 0D [4] 68 8C 06 00 00 }
	condition:
		#pattern == 1	
}


rule NF_CPD
{
	meta:
		script = "log \"NF_CPD=0x{@pattern}\""
		script = "lblset @pattern, GetStuffProps"
	strings:
		$pattern = { 55 8B EC 53 [24] 8B 4E 08 89 50 04 8B 56 0C 89 48 08 8B 4E 10 89 50 0C 8B 56 14 89 48 10 }
	condition:
		#pattern == 1	
}

rule NP_LK1
{
	meta:
		script = "$result = [@pattern + 0x05]"
		script = "log \"NP_LK1=0x{$result}\""
		script = "lblset $result, VisibleRange"
	strings:
		$pattern = { D9 56 28 D9 05 [4] D9 56 2C D9 CC D9 56 40 D9 05 [4] D9 5E 44 }
	condition:
		#pattern == 1	
}


rule NP_LK2
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"NP_LK2=0x{$result}\""
		script = "lblset $result, CreatedRange"
	strings:
		$pattern = { D9 05 [4] 8B 0D [4] D9 5D CC D9 05 [4] 6A 01 D9 5D D0 68 00 00 00 C8 }
	condition:
		#pattern == 1	
}


rule HF_NRB
{
	meta:
		script = "log \"HF_NRB=0x{@pattern},90e9\""
		//script = "lblset @pattern, HF_NRB"
	strings:
		$pattern = { 0F 84 1D 03 00 00 8B 85 [4] 8B B4 C5 [4] 8B 8D [4] 56 BF 01 00 00 00 }
	condition:
		#pattern == 1	
}

rule HF_NRC
{
	meta:
		script = "$result = @pattern + 0x10"
		script = "log \"HF_NRC=0x{$result},90e9\""
		//script = "lblset $result, HF_NRC"
		
		script = "$result = @pattern + 0x05 + [@pattern + 0x01]"
		script = "lblset $result, GetVisibleRange"
		
		script = "$result = @pattern + 0x24 + [@pattern + 0x20]"
		script = "lblset $result, GetCreatedRange"
	strings:
		$pattern = { E8 [4] DC 9D 78 FF FF FF DF E0 F6 C4 41 0F 85 [4] D9 45 80 DD 9D 78 FF FF FF E8 }
	condition:
		#pattern == 1	
}

rule HF_NRD
{
	meta:
		script = "log \"HF_NRD=0x{@pattern},eb1e\""
		//script = "lblset @pattern, HF_NRD"
	strings:
		$pattern = { 7A 3E D9 85 F8 D3 FF FF DD 9D F0 D3 FF FF E8 [4] DC 9D F0 D3 FF FF DF E0 F6 C4 41 7A ?? 6A 31 57 }
	condition:
		#pattern == 1	
}

rule NF_RAC
{
	meta:
		script = "$result = @pattern"
		script = "log \"NF_RAC=0x{$result}\""
		script = "lblset $result, ClearPlayerAction"
	strings:
		$pattern = { 53 56 8B F1 33 DB 8D 86 [4] 50 89 9E [4] 89 9E [4] 89 9E [4] 89 9E [4] 89 9E [4] 88 9E [4] E8 [4] 68 40 18 00 00 88 9E [4] 53 81 C6 00 02 00 00 }
	condition:
		#pattern == 1	
}

rule NP_ROT
{
	meta:
		script = "$result = [@pattern + 0x21]"
		script = "log \"NP_ROT=0x{$result}\""
		script = "lblset $result, WndSizeObj"
	strings:
		$pattern = { B8 89 88 88 88 F7 E9 03 D1 C1 FA 04 8B CA C1 E9 1F 03 CA 8B 15 [4] 89 0D [4] 52 B9 }
	condition:
		#pattern == 1	
}

rule NP_TXT
{
	meta:
		script = "$result = [@pattern + 0x0c]"
		script = "log \"NP_TXT=0x{$result}\""
		script = "lblset $result, TextObj"
	strings:
		$pattern = { 3D CB 00 00 00 0F 85 [4] A1 [4] 80 B8 3C 01 00 00 00 0F 85 [4] 80 B8 1C 02 00 00 00 }
	condition:
		#pattern == 1	
}

rule HC_DST
{
	meta:
		script = "$result = @pattern + 0x09"
		script = "log \"HC_DST=0x{$result},0x0c\""
		//script = "lblset $result, HC_DST"
	strings:
		$pattern = { 6A 00 68 20 04 00 00 FF D2 83 F8 03 75 07 C7 45 0C 05 00 00 00 D9 45 08 DB 45 0C }
	condition:
		#pattern == 1	
}

rule NP_CRS
{
	meta:
		script = "$result = [@pattern + 0x06]"
		script = "log \"NP_CRS=0x{$result}\""
		script = "lblset $result, CurSelObjID"
	strings:
		$pattern = { 6A 01 FF D2 C7 05 [4] FF FF 00 00 8B 4F 0A 8B 47 06 89 4D 98 }
	condition:
		#pattern == 1	
}


rule HC_XYZ
{
	meta:
		script = "$result = @pattern + 0x06"
		script = "log \"HC_XYZ=0x{$result},0x07\""
		script = "lblset $result, XYZConvert"
		script = "$result = [@pattern + 0x02]"
		script = "log \"NP_MX=0x{$result}\""
		script = "lblset $result, MouseX"
		script = "lblset $result+0x04, MouseY"
	strings:
		$pattern = { 52 68 [4] 68 FA 03 00 00 FF D0 83 F8 FF 0F 85 [4] 8B BF 6C 1A 00 00 }
	condition:
		#pattern == 1
}

rule HF_HPR
{
	meta:
		script = "$result = @pattern + 0x07"
		script = "log \"HF_HPR=0x{$result},00\""
		script = "$result = @pattern + 0x19"
		script = "log \"HF_HPB=0x{$result},9090\""
	strings:
		$pattern = { 8B B5 80 FE FF FF B9 01 00 00 00 89 8F C4 26 00 00 33 D2 39 0D [4] 75 0C 89 97 C4 26 00 00 89 97 04 26 00 00 }
	condition:
		#pattern == 1	
}

rule HC_HPR
{
	meta:
		script = "$result = @pattern + 0x1b"
		script = "log \"HC_HPR=0x{$result},0x07\""
		script = "$result = [@pattern + 0x1e]"
		script = "log \"NP_GOL=0x{$result}\""
		script = "lblset $result, ObjList"
	strings:
		$pattern = { 8B 75 08 C7 06 00 00 00 00 8B 15 [4] 81 FA FF FF 00 00 0F 84 FD 00 00 00 8B 04 95 }
	condition:
		#pattern == 1	
}


rule HF_HPP
{
	meta:
		script = "$result = @pattern + 0x12"
		script = "log \"HF_HPP=0x{$result},eb\""
	strings:
		$pattern = { 8B 46 F8 8B 50 04 8D 4E F8 FF D2 E9 [4] 85 DB 75 ?? 8D 4E F8 }
	condition:
		#pattern == 1	
}

rule HF_HMT
{
	meta:
		script = "$result = @pattern + 0x01"
		script = "log \"HF_HMT=0x{$result},00\""
	strings:
		$pattern = { B9 01 00 00 00 83 BE BC 03 00 00 04 89 8E B8 03 00 00 75 ?? 83 BE C0 03 00 00 00 75 }
	condition:
		#pattern == 1	
}

rule HF_HBD
{
	meta:
		script = "$result = @pattern + 0x10"
		script = "log \"HF_HBD=0x{$result},90e9\""
	strings:
		$pattern = { 55 8B EC 8B 45 08 53 56 57 8B F1 3D 56 04 00 00 0F 8F }
	condition:
		#pattern == 1	
}

rule HF_PKC
{
	meta:
		script = "$result = @pattern + 0x0d"
		script = "log \"HF_PKC=0x{$result},909090\""
	strings:
		$pattern = { 83 E0 02 C3 33 C0 66 39 81 24 43 00 00 0F 9F C0 C3 }
	condition:
		#pattern == 1	
}

rule HF_CRA
{
	meta:
		script = "$result = @pattern"
		script = "log \"HF_CRA=0x{$result},eb38\""
	strings:
		$pattern = { E8 [4] 3D 68 08 76 88 74 0E 3D 27 08 76 88 74 07 3D 6C 08 76 88 }
	condition:
		#pattern == 1	
}

rule HF_VEW
{
	meta:
		script = "$result = @pattern + 0x07"
		script = "log \"HF_VEW=0x{$result},eb\""
	strings:
		$pattern = { DE D9 DF E0 F6 C4 05 7A ?? D9 05 [4] D9 9B EC 00 00 00 A1 [4] A3 [4] 39 BB 00 01 00 00 74 ?? 39 BB F0 00 00 00 }
	condition:
		#pattern == 1	
}

rule NF_USS
{
	meta:
		script = "$result = @pattern + 0x1f + [@pattern + 0x1b]"
		script = "log \"NF_USS=0x{$result}\""
		script = "lblset $result, USeAtShortcut"
	strings:
		$pattern = { 43 83 C1 04 83 FB 1E 7C ?? 33 DB EB ?? 8B 0D [4] 8B 89 80 02 00 00 53 E8 [4] 8B BD 98 D2 FF FF 33 DB }
	condition:
		#pattern == 1	
}

rule NP_APP
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"NP_APP=0x{$result}\""
		script = "lblset $result, TlfMgr"
		
		script = "$result = [@pattern + 0x14]"
		script = "log \"NP_PLR=0x{$result}\""
		script = "lblset $result, PlayerObj"	
		
		script = "$result = @pattern + 0x12 + [@pattern + 0x0e]"
		script = "log \"NF_MSG=0x{$result}\""
		script = "lblset $result, OutputString"
	strings:
		$pattern = { 8B 0D [4] 68 E9 14 00 00 6A 09 E8 [4] 8B 0D [4] 53 E8 [4] 0F B7 46 02 66 83 F8 01 0F 84 [4] 66 83 F8 0A }
	condition:
		#pattern == 1	
}

rule NP_MPL
{
	meta:
		script = "$result = [@pattern + 0x2b]"
		script = "log \"NP_MPL=0x{$result}\""
		script = "lblset $result, TextPool"
	strings:
		$pattern = { 66 83 F8 01 0F 85 [4] 39 8F [4] 0F 85 [4] 89 8F [4] C7 87 [4] FF FF FF FF 8B 46 ?? 8B 0D [4] 50 E8 }
	condition:
		#pattern == 1	
}

rule NP_SLT
{
	meta:
		script = "$result = [@pattern + 0x13]"
		script = "log \"NP_SLT=0x{$result}\""
		script = "lblset $result, StuffList"
		
		script = "$result = [@pattern + 0x0d]"
		script = "log \"NP_SLC=0x{$result}\""
		script = "lblset $result, StuffCount"
		
	strings:
		$pattern = { BB 01 00 00 00 8D 71 12 89 45 08 8B 3D [4] 8B 0D [4] 69 FF 54 03 00 00 03 F9 3B CF }
	condition:
		#pattern == 1	
}

rule HF_JPB
{
	meta:
		script = "$result = @pattern + 0x09"
		script = "log \"HF_JPB=0x{$result},90e9\""
	strings:
		$pattern = { E8 [4] 33 C9 3B C1 0F 85 [4] 88 4E 20 89 8D [4] 89 4E 1C 56 8B CB E8 [4] FF 15 }
	condition:
		#pattern == 1	
}

rule HF_JPW
{
	meta:
		script = "log \"HF_JPW=0x{@pattern},90e9\""
	strings:
		$pattern = { 0F 84 [4] D9 45 08 8B 7E 14 D9 5D 88 D9 45 10 D9 5D 8C D9 03 D9 5D 80 D9 43 08 D9 5D 84 }
	condition:
		#pattern == 1	
}

rule HF_JPX
{
	meta:
		script = "$result = @pattern + 0x12"
		script = "log \"HF_JPX=0x{$result},eb57\""
	strings:
		$pattern = { 8B 8A 5C 4A 53 00 E8 [4] 80 BD [4] 01 0F 84 [4] D9 85 [4] 8D 85 [4] 50 6A 08 83 EC }
	condition:
		#pattern == 1	
}

rule HF_JPY
{
	meta:
		script = "$result = @pattern + 0x0a"
		script = "log \"HF_JPY=0x{$result},9090\""
	strings:
		$pattern = { 8B 4A 18 E8 [4] 85 C0 74 4E 8B 45 AC 8B 4D B0 }
	condition:
		#pattern == 1	
}

rule HF_JMP
{
	meta:
		script = "$result = @pattern + 0x08"
		script = "log \"HF_JMP=0x{$result},9090\""
	strings:
		$pattern = { 53 E8 [4] 84 C0 74 ?? D9 03 8B 75 B8 8D 45 90 50 68 F0 00 00 00 6A 00 }
	condition:
		#pattern == 1	
}

rule HF_JP0
{
	meta:
		script = "$result = @pattern + 0x07"
		script = "log \"HF_JP0=0x{$result},eb04\""
	strings:
		$pattern = { E8 [4] 85 C0 0F 84 [4] 53 57 8D 55 D4 52 83 EC 1C 8B FC B9 07 00 00 00 8D B5 60 FF FF FF F3 A5 8B 4D 84 }
	condition:
		#pattern == 1	
}

rule HF_JP1
{
	meta:
		script = "$result = @pattern + 0x17"
		script = "log \"HF_JP1=0x{$result},eb\""
	strings:
		$pattern = { D9 9D B0 FE FF FF D9 85 B0 FE FF FF D8 1D [4] DF E0 F6 C4 05 7A ?? C7 87 [4] 00 00 00 00 B8 01 00 00 00 }
	condition:
		#pattern == 1	
}

rule NP_ASL
{
	meta:
		script = "$result = [@pattern + 0x23]"
		script = "log \"NP_ASL=0x{$result}\""
		script = "lblset $result, GOList"
		
		script = "$result = [@pattern + 0x0f]"
		script = "log \"NP_ASN=0x{$result}\""
		script = "lblset $result, GOCount"
				
	strings:
		$pattern = { 8B 11 8B 42 04 53 53 6A 02 FF D0 33 F6 39 1D [4] 7E ?? EB ?? 8D A4 24 00 00 00 00 8B FF 8B 0C B5 }
	condition:
		#pattern == 1	
}

rule NP_FIX
{
	meta:
		script = "$result = [@pattern + 0x04]"
		script = "log \"NP_FIX=0x{$result}\""
		script = "lblset $result, IsRoleFixed"
	strings:
		//$pattern = { C7 05 [4] 00 00 00 00 C6 43 ?? 00 83 F8 02 74 ?? 83 F8 03 75 ?? 68 BF 02 00 00 EB ?? 83 F8 04 75 ?? 68 98 04 00 00 }
		$pattern = { 6A 00 C7 05 [4] 00 00 00 00 E8 [4] 8B 0D [4] 83 C4 04 68 DE 16 00 00 6A 09 }
	condition:
		#pattern == 1	
}

rule NP_ATV
{
	meta:
		script = "$result = [@pattern + 0x36]"
		script = "log \"NP_ATV=0x{$result}\""
		script = "lblset $result, CurSelObj"
	strings:
		$pattern = { 68 FF 00 00 00 53 6A 0A 6A 2E E8 [4] 68 FF 00 00 00 53 6A 0A E8 [4] 83 C4 2C B9 [4] 89 1D [4] E8 [4] 8B 15 [4] A1 }
	condition:
		#pattern == 1	
}

rule NP_TML
{
	meta:
		script = "$result = [@pattern + 0x10]"
		script = "log \"NP_TML=0x{$result}\""
		script = "lblset $result, TeamList"
		
		script = "$result = [@pattern + 0x05]"
		script = "log \"NP_TMF=0x{$result}\""
		script = "lblset $result, IsTeamed"
				
	strings:
		$pattern = { 55 8B EC 80 3D [4] 00 74 2D 8B 55 08 B9 [4] 8B 01 85 C0 74 14 80 B8 [4] 00 74 0B 0F BF 80 [4] 3B C2 74 ?? 83 C1 04 }
	condition:
		#pattern == 1	
}

rule NP_SHP
{
	meta:
		script = "$result = [@pattern + 0x25]"
		script = "log \"NP_SHP=0x{$result}\""
		script = "lblset $result, IsShopPrepared"
		script = "lblset $result+0x01, IsShopOpepend"
	strings:
		$pattern = { 83 FF 02 7C ?? 83 FF 0B 7E ?? 8D 57 C5 83 FA 09 0F 87 [4] 83 3D [4] FF 0F 85 [4] 80 3D [4] 00 }
	condition:
		#pattern == 1	
}

rule NP_RSL
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"NP_RSL=0x{$result}\""
		script = "lblset $result, RoleShopList"
	strings:
		$pattern = { C6 83 [4] 00 C7 83 [4] FF FF FF FF 85 C0 0F 84 [4] 6A 00 6A FF 8B C8 E8 [4] E9 [4] 0F B7 4C 39 06 }
	condition:
		#pattern == 1	
}

rule NP_MSD
{
	meta:
		script = "$result = [@pattern + 0x1f]"
		script = "log \"NP_MSD=0x{$result}\""
		script = "lblset $result, MouseClick"
	strings:
		$pattern = { 3D B1 39 0C 00 74 ?? 3D B2 39 0C 00 74 ?? 3D 79 3A 0C 00 74 ?? 52 8B CE E8 [4] 83 3D [4] 00 }
	condition:
		#pattern == 1	
}

rule NF_GOM
{
	meta:
		script = "$result = @pattern"
		script = "log \"NF_GOM=0x{$result}\""
		script = "lblset $result, GotoMap"
		
		script = "$result = [@pattern + 0x48]"
		script = "log \"NP_GOX=0x{$result}\""
		script = "lblset $result, GomapX"
		script = "lblset $result+0x04, GomapY"
		script = "lblset $result+0x08, GomapZ"
	strings:
		$pattern = { 55 8B EC B8 [57] 83 3D [4] 00 74 ?? D9 05 [4] D9 5D 0C D9 05 [4] D9 5D 10 D9 05 [4] D9 5D 14 8B 0D [4] 8B 81 [4] 80 B8 [4] 00 }
	condition:
		#pattern == 1	
}

rule NF_FUS
{
	meta:
		script = "$result = @pattern"
		script = "log \"NF_FUS=0x{$result}\""
		script = "lblset $result, UseStuff"
	strings:
		$pattern = { 55 8B EC 6A FF [80] 83 FB 01 74 ?? 83 FB 0D 74 ?? 83 FB 45 74 ?? 83 FB 3C 74 ?? 83 FB 7B 74 ?? 81 FB AB 00 00 00 0F 85 [4] EB ?? 81 FB AB 00 00 00 }
	condition:
		#pattern == 1	
}

rule HE_RSP
{
	meta:
		script = "$result = @pattern"
		script = "log \"HE_RSP=0x{$result}\""
		script = "lblset $result, Response"
	strings:
		$pattern = { 55 8B EC B8 [93] 83 FF 74 74 ?? 83 FF 67 74 ?? 83 FF 68 74 ?? 83 FF 6B 74 ?? 83 FF 65 74 ?? 83 FF 66 }
	condition:
		#pattern == 1	
}

rule NF_ATK
{
	meta:
		script = "$result = @pattern"
		script = "log \"NF_ATK=0x{$result}\""
		script = "lblset $result, NormalAttack"
	strings:
		$pattern = { 55 8B EC B8 [63] 3D 01 12 7A 00 75 ?? 8B CF E8 [4] 5F 8B 4D FC 33 CD E8 [4] 8B E5 5D C2 04 00 3D 02 12 7A 00 }
	condition:
		#pattern == 1	
}

rule HF_AT0
{
	meta:
		script = "$result = @pattern + 0x0c"
		script = "log \"HF_AT0=0x{$result},eb1a\""
		
		script = "$result = @pattern + 0x28 + [@pattern + 0x24]"
		script = "log \"NF_OSM=0x{$result}\""
		script = "lblset $result, OneShootMove"
	strings:
		$pattern = { 8B 8E [4] 8B 96 [4] 6A 02 83 EC 0C 8B C4 89 08 8B 8E [4] 89 50 ?? 89 48 ?? 8B CE E8 }
	condition:
		#pattern == 1	
}

rule HF_AT1
{
	meta:
		script = "$result = @pattern + 0x07"
		script = "log \"HF_AT1=0x{$result},9090\""
	strings:
		$pattern = { 80 B8 [4] 00 75 ?? 56 68 F6 03 00 00 8B CB C6 83 [4] 01 E8 [4] 56 8B CB C7 46 [4] 00 }
	condition:
		#pattern == 1	
}

rule HF_AT2
{
	meta:
		script = "$result = @pattern"
		script = "log \"HF_AT2=0x{$result},eb39\""
	strings:
		$pattern = { 75 ?? 8B 86 [4] 83 F8 02 0F 84 [4] 83 F8 03 0F 84 [4] 83 F8 05 0F 84 [4] 8B 86 [4] 83 F8 03 }
	condition:
		#pattern == 1	
}

rule HF_AT3
{
	meta:
		script = "$result = @pattern + 0x27"
		script = "log \"HF_AT3=0x{$result},eb04\""
	strings:
		$pattern = { 8B 8D [4] 8B 94 8B [4] 80 BA [4] 00 8B BD [4] 75 ?? 57 E8 [4] 83 C4 04 85 C0 0F 84 8D FB FF FF 8B 8D [4] 57 E8 }
	condition:
		#pattern == 1	
}

rule HF_AT4
{
	meta:
		script = "$result = @pattern + 0x09"
		script = "log \"HF_AT4=0x{$result},eb0f\""
	strings:
		$pattern = { 8B 87 [4] 83 F8 03 74 ?? 83 F8 04 74 ?? 83 F8 08 74 ?? 83 F8 09 74 }
	condition:
		#pattern == 1	
}

rule HF_AT5
{
	meta:
		script = "$result = @pattern + 0x18"
		script = "log \"HF_AT5=0x{$result},9090\""
	strings:
		$pattern = { C7 83 [4] 01 00 00 00 C7 46 ?? 03 00 00 00 80 BB [4] 00 75 ?? 81 7E [4] ?? 75 ?? D9 83 [4] 6A 02 }
	condition:
		#pattern == 1	
}

rule HF_HSN
{
	meta:
		script = "$result = @pattern + 0x2b"
		script = "log \"HF_HSN=0x{$result},eb03\""
		
		script = "$result = @pattern + 0x30 + [@pattern + 0x2c]"
		script = "lblset $result, ShowDialog"
	strings:
		$pattern = { 3D 21 03 00 00 74 ?? 3D A1 0F 00 00 74 ?? A1 [4] 83 B8 [4] 00 75 ?? 83 B8 [4] 00 75 ?? 8B 8F [4] E8 }
	condition:
		#pattern == 1	
}

rule HF_MV0
{
	meta:
		script = "$result = @pattern"
		script = "log \"HF_MV0=0x{$result},eb5b\""
	strings:
		$pattern = { 0F 8B [4] 8B 46 ?? 8B 4A ?? 3B C1 75 ?? 80 BE [4] 00 0F 85 [4] 3B C1 75 ?? 80 BE [4] 00 }
	condition:
		#pattern == 1	
}

rule HM_FLM
{
	meta:
		script = "$result = @pattern + 0x0e"
		script = "log \"HM_FLM=0x{$result}\""
	strings:
		$pattern = { D9 EE D9 9D [4] D9 85 [4] D9 85 [4] DE D9 DF E0 F6 C4 01 75 ?? B8 01 00 00 00 }
	condition:
		#pattern == 1	
}

rule NF_SAT
{
	meta:
		script = "$result = @pattern"
		script = "log \"NF_SAT=0x{$result}\""
		script = "lblset $result, SendSkillAttack"
	strings:
		$pattern = { 55 8B EC 83 [9] 89 45 ?? 8B 45 ?? 53 8B 5D ?? 56 8B 75 ?? 57 8B F9 89 45 ?? 85 C0 }
	condition:
		#pattern == 1	
}

rule HF_LKY
{
	meta:
		script = "$result = @pattern + 0x03"
		script = "log \"HF_LKY=0x{$result},7444\""
	strings:
		$pattern = { 83 F8 08 74 ?? 83 F8 65 74 ?? 83 F8 1A 74 ?? 83 F8 1B 74 ?? 83 F8 06 74 ?? 83 F8 6B 75 }
	condition:
		#pattern == 1	
}

rule NP_NET
{
	meta:
		script = "$result = @pattern"
		script = "log \"NF_PIK=0x{$result}\""
		script = "lblset $result, PickRemote"
		
		script = "$result = [@pattern + 0x58]"
		script = "log \"NP_NET=0x{$result}\""
		script = "lblset $result, Network"
		
		script = "$result = @pattern + 0x72 + [@pattern + 0x6e]"
		script = "log \"NF_SND=0x{$result}\""
		script = "lblset $result, SendPack"
					
	strings:
		$pattern = { 55 8B EC B8 [82] 8B 0D [4] 50 C7 85 F6 D7 FF FF 0B 00 08 00 89 95 FE D7 FF FF E8 8E 20 00 00 8B 4D FC }
	condition:
		#pattern == 1	
}


rule NF_FMV
{
	meta:
		script = "$result = @pattern"
		script = "log \"NF_FMV=0x{$result}\""
		script = "lblset $result, Move_Attack"
	strings:
		$pattern = { 53 8B DC 83 [135] D9 95 [4] D9 95 [4] D9 95 [4] D9 95 [4] D9 95 [4] D9 95 [4] F6 C1 01 }
	condition:
		#pattern == 1	
}

rule NF_FSM
{
	meta:
		script = "$result = @pattern + 0x14 + [@pattern + 0x10]"
		script = "log \"NF_FSM=0x{$result}\""
		script = "lblset $result, MoveStuff"
	strings:
		$pattern = { 8B 81 [4] 52 8B 91 [4] 50 52 E8 [4] 5F C7 86 [4] FF FF FF FF }
	condition:
		#pattern == 1	
}


rule NF_FMU
{
	meta:
		script = "$result = @pattern"
		script = "log \"NF_FMU=0x{$result}\""
		script = "lblset $result, ClickButton"
	strings:
		$pattern = { 55 8B EC B8 [56] 8B 80 [4] 85 C0 74 21 83 78 ?? 00 74 ?? 6A 28 6A 09 E8 }
	condition:
		#pattern == 1	
}

rule NP_PET
{
	meta:
		script = "$result = [@pattern + 0x11]"
		script = "log \"NP_PET=0x{$result}\""
		script = "lblset $result, PetInfo"
	strings:
		$pattern = { 6A FF 8D 70 ?? 6A 14 8D 58 ?? 05 FE 01 00 00 56 68 [4] 89 45 }
	condition:
		#pattern == 1	
}


rule NF_PEA
{
	meta:
		script = "$result = @pattern"
		script = "log \"NF_PEA=0x{$result}\""
		script = "lblset $result, PetAction"
		
		script = "$result = @pattern + 0x98 + [@pattern + 0x94]"
		script = "log \"NF_PEC=0x{$result}\""
		script = "lblset $result, PetCall"
				
	strings:
		$pattern = { 55 8B EC 8B [119] 6A 00 83 C1 08 6A 00 68 79 04 00 00 FF D2 5D C2 04 00 8B 89 [4] E8 [4] 5D C2 04 00 }
	condition:
		#pattern == 1	
}

rule HF_BOW
{
	meta:
		script = "$result = @pattern + 0x19"
		script = "log \"HF_BOW=0x{$result},eb\""
	strings:
		$pattern = { 81 F9 E8 CD 9A 3B 76 ?? 8B 35 [4] 85 F6 74 29 83 BE [4] 00 74 }
	condition:
		#pattern == 1	
}

rule HR_SMT
{
	meta:
		script = "log \"HR_SMT=0x{@pattern}\""	
		script = "$result = @pattern + 0x05 + [@pattern + 0x01]"
		script = "lblset $result, PrintMonsterTitle"
	strings:
		$pattern = { E8 [4] 8B 47 ?? 8B 50 ?? 6A 00 8D 4F ?? 6A 00 68 20 04 00 00 FF D2 83 F8 01 }
	condition:
		#pattern == 1	
}

rule HR_SPS
{
	meta:
		script = "log \"HR_SPS=0x{@pattern+0x03}\""	
		script = "$result = @pattern + 0x08 + [@pattern + 0x04]"
		script = "lblset $result, PrintPlayerTitle"
	strings:
		$pattern = { D9 1C 24 E8 [4] D9 46 ?? 8B 95 [4] 8B 0B 52 8D 85 [4] 50 51 8B 0D [4] 83 EC 0C }
	condition:
		#pattern == 1	
}

rule NP_PRL
{
	meta:
		script = "$result = [@pattern + 0x0e]"
		script = "log \"NP_PRL=0x{$result}\""
		script = "lblset $result, PlayerList"
	strings:
		$pattern = { 3D B8 0B 00 00 73 0D 69 C0 AC 01 00 00 05 [4] 5D C3 33 C0 5D C3 }
	condition:
		#pattern == 1	
}

rule NP_MTL
{
	meta:
		script = "$result = [@pattern + 0x0d]"
		script = "log \"NP_MTL=0x{$result}\""
		script = "lblset $result, MonsterList"
	strings:
		$pattern = { 6B C0 5C 32 C9 88 88 [4] 88 88 [4] 5D C2 04 00 }
	condition:
		#pattern == 1	
}


rule NP_BWT
{
	meta:
		script = "$result = [@pattern + 0x0e]"
		script = "log \"NP_BWT=0x{$result}\""
		script = "lblset $result, ByworkType"
	strings:
		$pattern = { 68 BE 09 00 00 6A 09 E8 [4] C7 05 [4] 01 00 01 00 EB }
	condition:
		#pattern == 1	
}

rule NP_CKP
{
	meta:
		script = "$result = [@pattern + 0x17]"
		script = "log \"NP_CKP=0x{$result}\""
		script = "lblset $result, StabberPoint"
	strings:
		$pattern = { 8B 56 1A 89 15 [4] 8B 46 1E A3 [4] 0F BF 46 22 39 05 [4] 7D }
	condition:
		#pattern == 1	
}

rule HF_MRF
{
	meta:
		script = "$result = @pattern + 0x06"
		script = "log \"HF_MRF=0x{$result},00\""
	strings:
		$pattern = { C7 86 [4] 05 00 00 00 C7 46 ?? 06 00 00 00 E9 [4] C7 86 [4] 01 00 00 00 FF D7 83 BE [4] 00 }
	condition:
		#pattern == 1	
}

rule NP_ATS
{
	meta:
		script = "$result = [@pattern + 0x07]"
		script = "log \"NP_ATS=0x{$result}\""
		script = "lblset $result, AttackSkill"
	strings:
		$pattern = { 56 68 00 40 69 00 68 [4] E8 [4] 56 68 00 50 2E 00 }
	condition:
		#pattern == 1	
}

rule NF_WXN
{
	meta:
		script = "$result = @pattern + 0x31 + [@pattern + 0x2d]"
		script = "log \"NF_WXN=0x{$result}\""
		script = "lblset $result, LoadWxName"
	strings:
		$pattern = { C7 85 [4] 5A 00 00 00 C7 85 [4] 17 00 04 00 E8 [4] 6A 00 8B CE E8 [4] E9 [4] 3B 7B ?? 75 ?? E8 }
	condition:
		#pattern == 1	
}

rule HF_PKN
{
	meta:
		script = "$result = @pattern + 0x06"
		script = "log \"HF_PKN=0x{$result},eb\""
	strings:
		$pattern = { 81 F9 41 1F 00 00 75 ?? 8B 15 [4] 83 BA [4] 00 0F 85 [4] 8B 85 [4] 50 C7 03 FF FF FF FF 8B 0D [4] 68 9F 0B 00 00 E8 }
	condition:
		#pattern == 1	
}

rule HF_PK1
{
	meta:
		script = "$result = @pattern + 0x0c"
		script = "log \"HF_PK1=0x{$result},eb\""
		
		script = "$result = [@pattern + 0x07]"
		script = "log \"NP_FPK=0x{$result}\""
		script = "lblset $result, ForcePK"
	strings:
		$pattern = { 3B 46 14 75 ?? 83 3D [4] 00 7E ?? E8 [4] 85 C0 75 ?? D9 86 [4] 8D 4D }
	condition:
		#pattern == 1	
}


rule HF_PK2
{
	meta:
		script = "log \"HF_PK2=0x{@pattern},eb04\""
	strings:
		$pattern = { 0F 85 [4] A1 [4] 3D 8D 23 00 00 0F 84 [4] 3D 29 23 00 00 0F 84 [4] 3D F1 23 00 00 0F 84 [4] 3D 21 03 00 00 }
	condition:
		#pattern == 1	
}

rule NF_MPP
{
	meta:
		script = "$result = @pattern + 0x11 + [@pattern + 0x0d]"
		script = "log \"NF_MPP=0x{$result}\""
		script = "lblset $result, CheckSafeArea"
		
		script = "$result = [@pattern + 0x02]"
		script = "log \"NP_MPM=0x{$result}\""
		script = "lblset $result, CurMapObj"
		
		script = "log \"NI_MEO=0x534a5c\""

		script = "$result = @pattern + 0x1d"
		script = "log \"HF_PK3=0x{$result},eb\""
		
	strings:
		$pattern = { 8B 15 [4] 8B 8A 5C 4A 53 00 E8 [4] 8B 85 [4] 0B 85 [4] 75 ?? E8 [4] 85 C0 74 ?? 85 F6 74 }
	condition:
		#pattern == 1	
}


rule HR_ROS
{
	meta:
		script = "$result = @pattern + 0x01"
		script = "log \"HR_ROS=0x{$result}\""
		script = "$result = @pattern + 0x06 + [@pattern + 0x02]"
		script = "lblset $result, find_object_sid"
	strings:
		$pattern = { 56 E8 [4] 8B F0 83 C4 18 85 F6 74 36 83 7E 08 2E 75 30 C7 86 [4] 01 00 00 00 }
	condition:
		#pattern == 1	
}

rule NP_THL
{
	meta:
		script = "$result = [@pattern + 0x1a]"
		script = "log \"NP_THL=0x{$result}\""
		script = "lblset $result, ThlAttackMgr"
	strings:
		$pattern = { 83 3D [4] 0E 75 ?? 0F B7 17 39 15 [4] 75 ?? 39 5E ?? 74 ?? A1 [4] 85 C0 75 ?? E8 }
	condition:
		#pattern == 1	
}

rule NP_ZD
{
	meta:
		script = "$result = [@pattern + 0x01]"
		script = "log \"NP_ZD=0x{$result}\""
		script = "lblset $result, ZdMgr"
	strings:
		$pattern = { A1 [4] 85 C0 75 05 E8 [4] 8B 0D [4] 68 CA 00 00 00 E8 [4] 6A 05 6A 19 8B CE E8 }
	condition:
		#pattern == 1	
}

rule HF_FMS
{
	meta:
		script = "$result = @pattern + 0x20"
		script = "log \"HF_FMS=0x{$result},90e9\""
	strings:
		$pattern = { 81 85 [4] 54 03 00 00 83 C6 04 81 FE 24 05 00 00 0F 8C [4] 83 BD [4] 00 0F 85 [4] 8B 0D [4] 68 E9 00 00 00 6A 09 E8 }
	condition:
		#pattern == 1	
}

rule address_BagList
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "log \"NP_LBG=0x{$result}\""
		script = "lblset $result, BagList"
	strings:
		$pattern = { 8B 35 [4] 33 C9 8D 86 [4] BF BC CC 9A 3B 90 }
	condition:
		#pattern == 1	
}

rule address_MyShopList
{
	meta:
		script = "$result = [@pattern + 0x16]"
		script = "log \"NP_LMS=0x{$result}\""
		script = "lblset $result, MyShopList"
	strings:
		$pattern = { 68 A7 0D 00 00 56 6A 09 6A 00 8B C8 E8 [4] EB ?? 33 C0 A3 }
	condition:
		#pattern == 1
}

rule address_PlayerShopList
{
	meta:
		script = "$result = [@pattern + 0x30]"
		script = "log \"NP_LPS=0x{$result}\""
		script = "lblset $result, PlayerShopList"
	strings:
		$pattern = { 68 F4 23 00 00 E8 [20] 68 B4 0D 00 00 ?? 6A 08 6A 00 [2] E8 [4] EB ?? 33 C0 A3 }
	condition:
		#pattern == 1
}

rule address_MakerMenuList
{
	meta:
		script = "$result = [@pattern + 0x12]"
		script = "log \"NP_LMM=0x{$result}\""
		script = "lblset $result, MakerMenuList"
	strings:
		$pattern = { 6A 5D ?? 6A 64 ?? 8B C8 E8 [4] EB ?? 33 C0 A3 [4] 8B 8E }
	condition:
		#pattern == 1
}

rule address_MakerReadyList
{
	meta:
		script = "$result = [@pattern + 0x13]"
		script = "log \"NP_LMR=0x{$result}\""
		script = "lblset $result, MakerReadyList"
	strings:
		$pattern = { 6A 71 56 6A 73 6A 00 8B C8 E8 [4] EB ?? 33 C0 A3 }
	condition:
		#pattern == 1
}

rule address_BreakerList
{
	meta:
		script = "$result = [@pattern + 0x16]"
		script = "log \"NP_LBK=0x{$result}\""
		script = "lblset $result, BreakerList"
	strings:
		$pattern = { 68 85 00 00 00 56 6A 6C 6A 00 [2] E8 [4] EB ?? 33 C0 A3 }
	condition:
		#pattern == 1
}


rule address_end
{
	meta:
		script = "log"
		script = "log"
	condition:
		true
}
