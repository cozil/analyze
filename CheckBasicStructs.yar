rule CheckBasicStructs_start
{
	meta:
		load = "utils/basicStructs.scr"
	condition:
		true
}

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

rule Check_RX_MAKER_ITEM
{
	meta:
		script = "$result1 = [@pattern + 0x24]"
		script = "Type.size RX_MAKER_ITEM"
		script = "cmp $result,$result1"
		script = "jnz _FAIL"
		script = "Type.print RX_MAKER_ITEM,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
		script = "jmp _EXIT"
		script = "_FAIL:"
		script = "log \"Size of RX_MAKER_ITEM has changed to 0x{$result1}\""
		script = "msg \"RX_MAKER_ITEM结构发生改变\""
		script = "_EXIT:"
	strings:
		$pattern = { C1 E1 04 8B 84 31 [4] 03 CE 3B 81 [4] 74 ?? 8B 55 ?? 8B 75 ?? 39 30 75 ?? 39 50 ?? 74 ?? 05 }
	condition:
		#pattern == 1
}

rule Check_CRxBaseStuff
{
	meta:
		script = "$result1 = [@pattern + 0x0c]"
		script = "Type.size CRxBaseStuff"
		script = "cmp $result,$result1"
		script = "jnz _FAIL"
		script = "Type.print CRxBaseStuff,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
		script = "jmp _EXIT"
		script = "_FAIL:"
		script = "log \"Size of CRxBaseStuff has changed to 0x{$result1}\""
		script = "msg \"CRxBaseStuff结构发生改变\""
		script = "_EXIT:"
	strings:
		$pattern = { 83 F8 07 74 ?? 83 F8 0A 75 ?? 81 EC 54 03 00 00 [2] B9 D5 00 00 00 }
	condition:
		#pattern == 1
}

rule Check_CRxShopInfo
{
	//CRxShopInfo结构长度是通过累加计算得到，以下特征码包含了累加过程
	//只要找到特征码则表示结构大小未变化
	meta:
		script = "Type.print CRxShopInfo,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	strings:
		$pattern = { 8D 3C 80 03 FF 03 FF 03 FF 89 96 [4] 83 BF [4] FF [2] 80 BF [4] 00 }
	condition:
		#pattern == 1
}

rule Check_CRxRoleInfo
{
	//只要找到特征码则表示结构大小未变化
	meta:
		script = "Type.print CRxRoleInfo,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	strings:
		//检查结构大小的特征码
		$pattern = { B8 0B 00 00 [4] AC 01 00 00 }
		//检查成员roleState偏移的特征码
		//如果未找到，将 94 00 00 00 屏蔽掉再查找
		$pattern1 = { F7 ?? 94 00 00 00 00 00 40 00 [7] 6A 00 68 00 00 40 00 68 57 04 00 00 }
	condition:
		$pattern and $pattern1
}