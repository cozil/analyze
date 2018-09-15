rule CRxNpc_start
{
	meta:
		script = "log \"struct CRxNpc {\""
		script = "$offset = 0"
	condition:
		true
}

//对象指针位移
//与x_monflag的特征码相同
rule CRxNpc_offset__
{
	meta:		
		script = "$offset = 0x100 - byte:[@pattern + 0x02]"
		script = "log \"//\""
		script = "log \"//对象指针位移可能是：{d:-$offset}，部分成员偏移需要减去该值\""	
		script = "log \"//\""
	strings:
		$pattern = { 8D 4E ?? E8 [4] 81 3D [4] 41 1F 00 00 74 ?? 83 BE [4] 00 75 ?? 81 BE [4] 0F 27 00 00 }
	condition:
		#pattern == 1	
}

//014 int sessionid;
rule CRxNpc_sessionid
{
	meta:
		script = "$result = byte:[@pattern + 0x26] - $offset"
		script = "log \"//NPC会话ID -{d:$offset}\""
		script = "log \"/*{p:$result}*/    int sessionid;\""
	strings:
		$pattern = { 3D 81 0C 00 00 [2] 3D 59 1B 00 00 [2] 3D BD 1B 00 00 [2] C7 83 [4] 07 00 00 00 5B 8B E5 5D C3 8B 43 }
	condition:
		#pattern == 1	
}



//354 int x_showblood;
rule CRxNpc_x_showblood
{
	meta:
		script = "$result = [@pattern + 0x13]"
		script = "log \"//显示怪物血条\""
		script = "log \"/*{p:$result}*/    int x_showblood;\""
	strings:
		$pattern = { E8 [4] 81 3D [4] 41 1F 00 00 74 ?? 83 BE [4] 00 75 ?? 81 BE [4] 0F 27 00 00 }
	condition:
		#pattern == 1	
}

//35c float	x_distance;
rule CRxNpc_x_distance
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"//怪物与玩家直线距离\""
		script = "log \"/*{p:$result}*/    float x_distance;\""
	strings:
		$pattern = { D9 86 [4] DC 1D [4] DF E0 F6 C4 41 [2] C7 86 [4] 00 00 00 00 [2] 89 8E [4] 81 3D [4] 29 A0 00 00 }
	condition:
		#pattern == 1	
}

//360 char x_name[0x20];
rule CRxNpc_x_name
{
	meta:
		script = "$result = [@pattern + 0x02] - $offset"
		script = "log \"//怪物名称 -{d:$offset}\""
		script = "log \"/*{p:$result}*/    char x_name[0x20];\""
	strings:
		$pattern = { 8D 9F [4] 85 DB 0F 84 [4] A1 [4] 8B 10 6A 00 6A 1C 50 8B 82 [4] FF D0 }
	condition:
		#pattern == 1	
}

//3B0 int x_monflag;
//与CRxNpc_x_showblood的特征码相同
rule CRxNpc_x_monflag
{
	meta:		
		script = "$result = [@pattern + 0x1f]"
		script = "log \"//0x2710或以上的值为怪物,否则为NPC\""
		script = "log \"/*{p:$result}*/    int x_monflag;\""
		
	strings:
		$pattern = { 8D 4E ?? E8 [4] 81 3D [4] 41 1F 00 00 74 ?? 83 BE [4] 00 75 ?? 81 BE [4] 0F 27 00 00 }
	condition:
		#pattern == 1	
}

//3B4 short x_attack;
rule CRxNpc_x_attack
{
	meta:		
		script = "$result = [@pattern + 0x1d] - $offset"
		script = "log \"//怪物正在攻击的玩家编号 -{d:$offset}\""
		script = "log \"/*{p:$result}*/    short x_attack;\""
		
	strings:
		$pattern = { 6A 01 50 6A 1C 8B CE E8 [4] 85 C0 0F 84 [4] 8B 46 ?? 3B C3 74 ?? 89 86 }
	condition:
		#pattern == 1	
}

//3B8 int x_visible;
rule CRxNpc_x_visible
{
	meta:		
		script = "$result = [@pattern + 0x16]"
		script = "log \"//怪物是否可见\""
		script = "log \"/*{p:$result}*/    int x_visible;\""
		
	strings:
		$pattern = { 6A 00 68 [4] 68 61 04 00 00 FF D2 8B 8D [4] 89 81 }
	condition:
		#pattern == 1	
}

////3BC int x_deadstatus;
//rule CRxNpc_x_deadstatus
//{
//	meta:		
//		script = "$result = [@pattern + 0x1d]"
//		script = "log \"//死亡变化状态\""
//		script = "log \"/*{p:$result}*/    int x_deadstatus;\""
//		
//	strings:
//		$pattern = { 81 C1 48 A8 00 00 E8 [4] E9 [4] 8B 86 [4] E9 [4] C7 86 [4] 05 00 00 00 }
//	condition:
//		#pattern == 1	
//}

//3BC int x_deadstatus;
//3C0 int x_dead;
rule CRxNpc_x_dead
{
	meta:
		script = "$result = [@pattern + 0x11] - $offset"
		script = "log \"//怪物死亡状态变化 -{d:$offset}\""
		script = "log \"/*{p:$result}*/    int x_deadstatus;\""
		script = "$result = [@pattern + 0x1b] - $offset"
		script = "log \"//怪物死亡标志 -{d:$offset}\""
		script = "log \"/*{p:$result}*/    int x_dead;\""
		
	strings:
		$pattern = { D9 E8 33 DB D9 9E [4] B8 FF FF 00 00 C7 86 [4] 02 00 00 00 C7 86 [4] 01 00 00 00 }
	condition:
		#pattern == 1
}

//3C8 int x_shootdown;
//3CC int x_shoottime;
rule CRxNpc_x_shoot
{
	meta:
		script = "$result = [@pattern + 0x2d]"
		script = "log \"//绝命技能可以使用标志\""
		script = "log \"/*{p:$result}*/    int x_shootdown;\""
		script = "$result = [@pattern + 0x27]"
		script = "log \"//绝命技施放前开始计时\""
		script = "log \"/*{p:$result}*/    int x_shoottime;\""
		
	strings:
		$pattern = { 3D 32 3C 00 00 [2] 3D 34 3C 00 00 [2] 3D 30 3F 00 00 [2] C7 86 [4] 01 00 00 00 8B 86 [4] 89 BE [4] 89 BE }
	condition:
		#pattern == 1
}

//5F4 int x_life;
//5F8 int x_grade;
rule CRxNpc_x_life
{
	meta:
		script = "$result = [@pattern + 0x02] - $offset"
		script = "log \"//怪物当前血值 -{d:$offset}\""
		script = "log \"/*{p:$result}*/    int x_life;\""
		script = "$result = [@pattern + 0x26] - $offset"
		script = "log \"//怪物等级 -{d:$offset}\""
		script = "log \"/*{p:$result}*/    int x_grade;\""
	strings:
		$pattern = { C7 86 [4] 00 00 00 00 81 3D [4] 29 A0 00 00 [2] 81 BE [4] 72 3F 00 00 0F BF 41 ?? 89 86 }
	condition:
		#pattern == 1
}

//610 int x_maxlife;
rule CRxNpc_x_maxlife
{
	meta:
		script = "$result = [@pattern + 0x0f] - $offset"
		script = "log \"//怪物最大血值 -{d:$offset}\""
		script = "log \"/*{p:$result}*/    int x_maxlife;\""
	strings:
		$pattern = { C7 86 [4] 00 00 00 00 8B 41 ?? 89 86 [4] 8B 86 [4] 3B 41 [28] 81 3D [4] 29 A0 00 00 }
	condition:
		#pattern == 1
}

//280 _mons_pos::pos
rule CRxNpc_mons_pos
{
	meta:
		script = "$result = [@pattern + 0x13]"
		script = "log \"//_mons_pos结构怪物坐标偏移为 0x{$result}\""
	strings:
		$pattern = { 46 83 C7 04 83 FE 05 7C DA 8B 45 9C FF 45 80 8B 55 8C 05 80 02 00 00 }
	condition:
		#pattern == 1

}

//1090 _mons_pos * x_pMpos;
rule CRxNpc_x_pMpos
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"//怪物坐标指针\""
		script = "log \"/*{p:$result}*/    _mons_pos * x_pMpos;\""
	strings:
		$pattern = { 8B B6 [4] 85 D2 [40] 81 C1 10 FC FF FF 81 F9 8F 00 00 00 }
	condition:
		#pattern == 1
}



//1428 int x_poison_num;
rule CRxNpc_x_poison_num
{
	meta:
		script = "$result = [@pattern + 0x09] - $offset"
		script = "log \"//怪物中毒数量（CK技能中毒数量）-{d:$offset}\""
		script = "log \"/*{p:$result}*/    int x_poison_num;\""
	strings:
		$pattern = { C7 45 ?? 00 00 FF FF 89 BE [4] 39 BE [4] 74 ?? 68 10 01 00 00 }
	condition:
		#pattern == 1
}

//1A18 int x_group;
rule CRxNpc_x_group
{
	meta:
		script = "$result = [@pattern + 0x0d]"
		script = "log \"//风云神物的势力状态，只有monflag = 3c0b 时才能使用\""
		script = "log \"/*{p:$result}*/    int x_group;\""
	strings:
		$pattern = { 81 F9 0B 3C 00 00 75 ?? 0F B6 D0 3B 96 [6] B8 05 00 00 00 E9 [4] 81 F9 5E 3C 00 00 0F 8C [4] 81 F9 6E 3C 00 00 0F 8F [4] 81 F9 60 3C 00 00 }
	condition:
		#pattern == 1
}

////1a18 int x_group;
//rule CRxEntity_x_group
//{
//	meta:
//		script = "$result = [@pattern + 0x23]"
//		script = "log \"/*{p:$result}*/    int x_group;\""
//	strings:
//		$pattern = { 81 FA A1 0F 00 00 75 ?? 83 F8 37 0F 84 [4] A0 [4] 81 F9 0B 3C 00 00 75 ?? 0F B6 D0 3B 96 }
//	condition:
//		#pattern == 1
//}



rule CRxNpc_end
{
	meta:
		script = "log };"
		script = "log"
		script = "log"
	condition:
		true
}
