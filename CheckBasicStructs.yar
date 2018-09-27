 rule Check_CRxSkillList
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.ad CRxSkillList,\"const static int MaxSize_ = 0x{$result};\""
		script = "$result1 = [@pattern + 0x10]"
		script = "Type.size CRxSkillList"
		script = "cmp $result,$result1"
		script = "jnz _FAIL"
		script = "Type.print CRxSkillItem,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
		script = "Type.print CRxSkillList,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
		script = "jmp _EXIT"
		script = "_FAIL:"
		script = "log \"Size of CRxSkillList has changed to 0x{$result1}\""
		script = "msg \"CRxSkillList/CRxSkillItem结构发生改变\""
		script = "_EXIT:"
	strings:
		$pattern = { 81 FF [4] 0F 8D [4] 8B CF 69 C9 [4] 8B B1 [4] 8D 99 [12] 14 FA 1E 00 [8] 78 FA 1E 00 [8] DC FA 1E 00 }
	condition:
		#pattern == 1
}

rule Check_RX_GAME_NPC
{
	meta:
		script = "$result1 = [@pattern + 0x19]"
		script = "Type.size RX_GAME_NPC"
		script = "cmp $result,$result1"
		script = "jnz _FAIL"
		script = "$result1 = [@pattern + 0x1f] - [@pattern + 0x10]"
		script = "Type.ad CRxSkillList,\"const static int MaxSize_ = 0x{$result1/$result};\""
		script = "Type.print RX_GAME_NPC,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
		script = "jmp _EXIT"
		script = "_FAIL:"
		script = "log \"Size of RX_GAME_NPC has changed to 0x{$result1}\""
		script = "msg \"RX_GAME_NPC结构发生改变\""
		script = "_EXIT:"
	strings:
		$pattern = { BE DE 27 00 00 [3] 75 [6] B8 [6] 74 ?? 05 [4] 41 3D }
	condition:
		#pattern == 1
}

rule Check_RX_SHOP_ITEM
{
	meta:
		script = "$result1 = byte:[@pattern + 3]"
		script = "Type.size RX_SHOP_ITEM"
		script = "cmp $result,$result1"
		script = "jnz _FAIL"
		script = "Type.print RX_SHOP_ITEM,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
		script = "jmp _EXIT"
		script = "_FAIL:"
		script = "log \"Size of RX_SHOP_ITEM has changed to 0x{$result1}\""
		script = "msg \"RX_SHOP_ITEM结构发生改变\""
		script = "_EXIT:"
	strings:
		$pattern = { 40 83 C1 ?? 83 F8 08 7C ?? 5F 5E 5D C2 04 00 6B C0 ?? 8D BC 38 [4] B9 [4] F3 A5 }
	condition:
		#pattern == 1
}