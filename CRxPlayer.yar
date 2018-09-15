rule CRxPlayer_start
{
	meta:
		script = "log \"struct CRxPlayer {\""
	condition:
		true
}

//014 int sessionid;
rule CRxPlayer_sessionid
{
	meta:
		script = "$result = byte:[@pattern + 0x02]"
		script = "log \"//会话ID\""
		script = "log \"/*{p:$result}*/    int sessionid;\""
	strings:
		$pattern = { 8B 47 ?? 8B 0D [4] 8D 72 ?? 3B C8 74 ?? 81 3D [4] 41 9C 00 00 [2] 81 3D [4] A5 9C 00 00 }
	condition:
		#pattern == 1
}

//018 char r_name[0x30];
rule CRxPlayer_r_name
{
	meta:
		script = "$result = byte:[@pattern + 0x1b]"
		script = "log \"//角色名称\""
		script = "log \"/*{p:$result}*/    char r_name[0x30];\""
	strings:
		$pattern = { 81 F9 FF FF 00 00 [2] 8B 34 8D [4] 85 F6 [2] 83 7E 08 31 [2] 8D 56 ?? 52 8D 8F [4] E8 }
	condition:
		#pattern == 1
}

//019A short r_zdgroup;
rule CRxPlayer_r_zdgroup
{
	meta:
		script = "$result = [@pattern + 0x16]"
		script = "log \"//真斗烈战、灵魂大战中区分敌友（不同为敌方）\""
		script = "log \"/*{p:$result}*/    short r_zdgroup;\""
	strings:
		$pattern = { 81 F9 41 9C 00 00 74 ?? 81 F9 A5 9C 00 00 75 ?? 8B 56 ?? 0F B7 82 [4] 8B 0D [4] 66 39 81 }
	condition:
		#pattern == 1
}

//1fc CRxSkillItem * r_skill_info;
rule CRxPlayer_r_skill_info
{
	meta:
		script = "$result = [@pattern + 0x15]"
		script = "log \"//正在使用的技能对象\""
		script = "log \"/*{p:$result}*/    CRxSkillItem * r_skill_info;\""
	strings:
		$pattern = { 69 D2 50 1A 00 00 69 C0 90 01 00 00 8D BC 02 [4] 89 BE }
	condition:
		#pattern == 1
}

//200 int r_ani_id;
//204 int r_skillid;
rule CRxPlayer_r_ani_id
{
	meta:
		script = "$result = [@pattern + 0x09]"
		script = "log \"//技能动作，置0即可屏蔽动画\""
		script = "log \"/*{p:$result}*/    int r_ani_id;\""
		script = "$result = [@pattern + 0x1f]"
		script = "log \"//最后一次使用的技能代码\""
		script = "log \"/*{p:$result}*/    int r_skillid;\""
	strings:
		$pattern = { 69 D2 84 01 00 00 89 84 3A [4] 8B 97 [4] 8B 46 ?? 69 D2 84 01 00 00 89 84 3A [80] 0F 27 00 00 }
	condition:
		#pattern == 1
}

//1a4c short r_select;
rule CRxPlayer_r_select
{
	meta:
		script = "$result = [@pattern + 0x16]"
		script = "log \"//当前选中的对象编号\""
		script = "log \"/*{p:$result}*/    short r_select;\""
	strings:
		$pattern = { 6A 01 68 50 04 00 00 8B CE FF D2 8B 46 ?? 8B 0D [4] 89 81 [4] EB ?? C7 85 [4] FF FF 00 00 }
	condition:
		#pattern == 1
}

//1a50 POINT3D r_destpos;
//1a68 short r_attack;
rule CRxPlayer_r_destpos
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"//角色正在移动的目标位置\""
		script = "log \"/*{p:$result}*/    POINT3D r_destpos;\""
		script = "$result = [@pattern + 0x0e]"
		script = "log \"//正在被攻击的怪物编号\""
		script = "log \"/*{p:$result}*/    short r_attack;\""
	strings:
		$pattern = { 8D 87 [4] 89 85 [4] C7 87 [4] FF FF 00 00 C7 87 [4] 00 00 00 00 C6 87 [4] 00 C7 05 [4] 00 00 00 00 }
	condition:
		#pattern == 1
}

//1a6c int r_action;
//与CRxPlayer_r_destpos相同
//rule CRxPlayer_r_action
//{
//	meta:
//		script = "$result = [@pattern + 0x23]"
//		script = "log \"//状态(1-移动 2-平砍攻击 5:医平砍/技攻击/加辅助 6-打坐 7-采药\""
//		script = "log \"/*{p:$result}*/    int r_action;\""
//	strings:
//		$pattern = { B8 01 00 00 00 E9 [4] 83 FA 78 0F 84 [4] 83 FA 01 0F 85 [4] E9 [4] 8B 87 [4] 8B C8 81 E1 FE 00 00 00 80 F9 FE }
//	condition:
//		#pattern == 1
//}

//1a6c int r_action;
//1a70 BYTE r_state;
//1a74 int r_state2;
rule CRxPlayer_r_action
{
	meta:
		script = "$result = [@pattern + 0x0f]"
		script = "log \"//状态(1-移动 2-平砍攻击 5:医平砍/技攻击/加辅助 6-打坐 7-采药\""
		script = "log \"/*{p:$result}*/    int r_action;\""
		script = "$result = [@pattern + 0x09]"
		script = "log \"//活动状态,00-完全静止 01-移动中或正在攻击	\""
		script = "log \"/*{p:$result}*/    BYTE r_state;\""
		script = "$result = [@pattern + 0x36]"
		script = "log \"//同上\""
		script = "log \"/*{p:$result}*/    int r_state2;\""
	strings:
		$pattern = { 83 BE [4] FF 88 86 [4] C7 86 [4] 00 00 00 00 74 ?? 80 BE [4] 00 74 ?? C7 86 [4] 02 00 00 00 EB ?? 89 86 [4] C7 86 [4] 00 00 00 00 FF D7 }
	condition:
		#pattern == 1
}

//1a80 float r_attacklen;
//1a84 int r_next_skillid;
rule CRxPlayer_r_attacklen
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"//当前技能的攻击距离\""
		script = "log \"/*{p:$result}*/    float r_attacklen;\""
		script = "$result = [@pattern + 0x0f]"
		script = "log \"//下一个攻击技能id\""
		script = "log \"/*{p:$result}*/    int r_next_skillid;\""
	strings:
		$pattern = { D9 9F [4] 8B CF E8 [4] 81 BF [4] 51 C8 2D 00 75 ?? 8B 87 [4] 3D 25 C7 2D 00 }
	condition:
		#pattern == 1
}



//1a84 int r_next_skillid;
//与CRxPlayer_r_destpos相同
rule CRxPlayer_r_next_skillid
{
	meta:
		script = "$result = [@pattern + 0x18]"
		script = "log \"//下一个攻击技能id\""
		script = "log \"/*{p:$result}*/    int r_next_skillid;\""
	strings:
		$pattern = { 8D 87 [4] 89 85 [4] C7 87 [4] FF FF 00 00 C7 87 [4] 00 00 00 00 C6 87 [4] 00 C7 05 [4] 00 00 00 00 }
	condition:
		#pattern == 1
}

//1c48 POINT3D r_destpos2;
//1c84 POINT3D r_currpos;
rule CRxPlayer_r_destpos2
{
	meta:
		script = "$result = [@pattern + 0x1d]"
		script = "log \"//必杀前调用移动函数使用的参数\""
		script = "log \"/*{p:$result}*/    POINT3D r_destpos2;\""
		script = "$result = [@pattern + 0x23]"
		script = "log \"//玩家当前坐标\""
		script = "log \"/*{p:$result}*/    POINT3D r_currpos;\""
	strings:
		$pattern = { 05 10 02 00 00 50 8D 8D [4] 51 8D 95 [4] 52 8B CF E8 [4] D9 87 [4] D9 87 [4] DE D9 }
	condition:
		#pattern == 1
}

//1cc0 char r_school[0x10];
rule CRxPlayer_r_school
{
	meta:
		script = "$result = [@pattern + 0x0a]"
		script = "log \"//角色门派\""
		script = "log \"/*{p:$result}*/    char r_school[0x10];\""
	strings:
		$pattern = { 55 8B EC 56 [4] 8D 86 [4] 89 08 89 48 04 89 48 08 66 89 48 0C [4] 88 48 0E }
	condition:
		#pattern == 1
}

//2304 int r_pet_ride_flag;
rule CRxPlayer_r_pet_ride_flag
{
	meta:
		script = "$result = [@pattern + 0x0f]"
		script = "log \"//宠物骑乘标记，0：没有骑乘，1：正在骑乘，大于1：已骑乘\""
		script = "log \"/*{p:$result}*/    int r_pet_ride_flag;\""
	strings:
		$pattern = { 81 63 ?? FF FF FF 7F 8B 0D [4] 83 B9 [4] 00 8B 43 ?? 8D 53 ?? 89 95 [6] 3D 25 C7 2D 00 [2] 3D 26 C7 2D 00 }
	condition:
		#pattern == 1
}

//230c int r_shop_sid;
//2310 char r_shopname[0xf8];
rule CRxPlayer_r_shop_sid
{
	meta:
		script = "$result = [@pattern + 0x12]"
		script = "log \"//开店标识，等于sessionid时表示在开店状态\""
		script = "log \"/*{p:$result}*/    int r_shop_sid;\""
		script = "$result = [@pattern + 0x2b]"
		script = "log \"//开店名称\""
		script = "log \"/*{p:$result}*/    r_shopname[0xf8];\""
	strings:
		$pattern = { B9 03 00 00 00 F7 F9 B8 01 00 00 00 3B D0 75 ?? 83 BE [4] FF 88 86 [4] C7 86 [4] 00 00 00 00 74 ?? 80 BE [4] 00 74 ?? C7 86 [4] 02 00 00 00 }
	condition:
		#pattern == 1
}

//2408 int r_jumpflag;
rule CRxPlayer_r_jumpflag
{
	meta:
		script = "$result = [@pattern + 0x1a]"
		script = "log \"//穿墙用，移动时调整为非0x0f值即可，否则遇到障碍物会停止前进\""
		script = "log \"/*{p:$result}*/    int r_jumpflag;\""
	strings:
		$pattern = { 8B 89 5C 4A 53 00 E8 [4] 80 BD [4] 01 0F 84 [4] 8B 97 [4] 8D B7 [4] 8B CE 89 95 [4] E8 }
	condition:
		#pattern == 1
}

//263c int r_light;
rule CRxPlayer_r_light
{
	meta:
		script = "$result = [@pattern + 0x07]"
		script = "log \"//轻功标志 1:15轻功疾风御气术 2:60轻功梯云纵 3/4:飞行状态 5:100轻功草上飞 6:疾龙一式 7:疾龙二式 8:疾龙三式\""
		script = "log \"/*{p:$result}*/    int r_light;\""
	strings:
		$pattern = { E8 [4] 8B 83 [4] 83 F8 03 74 ?? 83 F8 04 74 ?? 83 F8 08 74 ?? 83 F8 09 }
	condition:
		#pattern == 1
}

//2688 int r_run;
rule CRxPlayer_r_run
{
	meta:
		script = "$result = [@pattern + 0x28]"
		script = "log \"//当r_light==0时, 0:表示行走 1:表示跑\""
		script = "log \"/*{p:$result}*/    int r_run;\""
	strings:
		$pattern = { 3D 7A 90 06 00 [16] 81 E9 14 90 06 00 [11] 8B 86 }
	condition:
		#pattern == 1
}

//26c4 int r_visible;
rule CRxPlayer_r_visible
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"//玩家是否在场景中显示\""
		script = "log \"/*{p:$result}*/    int r_visible;\""
	strings:
		$pattern = { 89 81 [4] B9 01 00 00 00 33 D2 A1 [4] 3D 29 23 00 00 [2] 3D 8D 23 00 00 [2] 3D F1 23 00 00 }
	condition:
		#pattern == 1
}

//26fc int r_career;
rule CRxPlayer_r_career
{
	meta:
		script = "$result = [@pattern + 0x18]"
		script = "log \"//玩家职业，与CRxRoleInfo中的career值不一定相同\""
		script = "log \"/*{p:$result}*/    int r_career;\""
	strings:
		$pattern = { 83 7E 08 31 0F 85 [4] 8B 4E ?? 3B 4F ?? 0F 84 [4] 83 BE [4] 06 0F 85 [4] 80 BE [4] 00 }
	condition:
		#pattern == 1
}

//2700 int r_sex;
rule CRxPlayer_r_sex
{
	meta:
		script = "$result = [@pattern + 0x16]"
		script = "log \"//玩家性别\""
		script = "log \"/*{p:$result}*/    int r_sex;\""
	strings:
		$pattern = { 83 F8 76 [2] 83 F8 77 [2] 83 F8 02 [2] BA 01 00 00 00 39 93 }
	condition:
		#pattern == 1
}

//2778 int r_deadstate;
//与CRxPlayer_r_destpos相同
rule CRxPlayer_r_deadstate
{
	meta:
		script = "$result = [@pattern + 0x33]"
		script = "log \"//人物死亡状态，死亡时置2\""
		script = "log \"/*{p:$result}*/    int r_deadstate;\""
	strings:
		$pattern = { 8D 87 [4] 89 85 [4] C7 87 [4] FF FF 00 00 C7 87 [4] 00 00 00 00 C6 87 [4] 00 C7 05 [4] 00 00 00 00 }
		//offset:0x17
		//$pattern = { 6A 01 68 50 04 00 00 8B CE FF D0 B8 01 00 00 00 E9 [4] 8B 87 [4] DD D8 }
	condition:
		#pattern == 1
}

//33f0 int r_move_flag1;
//33f4 int r_move_flag2;
rule CRxPlayer_move_flag
{
	meta:
		script = "$result = [@pattern + 0x0a]"
		script = "log \"//两个标记为0时表示人物正在移动，瞬移使用，瞬移后置1\""
		script = "log \"/*{p:$result}*/    int r_move_flag1;\""
		script = "$result = [@pattern + 0x04]"
		script = "log \"/*{p:$result}*/    int r_move_flag2;\""
	strings:
		$pattern = { 33 C9 89 8F [4] 89 8F [4] C7 87 [4] 01 00 00 00 8B 87 [4] 3B C1 0F 84 [4] 8B 40 ?? 81 C7 68 1A 00 00 57 6A 1E }
	condition:
		#pattern == 1
}


//3408 int r_selected_flag;
rule CRxPlayer_r_selected_flag
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"//点击角色选中标记\""
		script = "log \"/*{p:$result}*/    int r_selected_flag;\""
	strings:
		$pattern = { 8B 88 [8] 80 BE [4] 00 [2] C7 85 [4] 80 00 00 00 [6] C7 85 [4] 00 08 00 00 }
	condition:
		#pattern == 1
}


//4298 int r_bow_gattack_id;
rule CRxPlayer_r_bow_gattack_id
{
	meta:
		script = "$result = [@pattern + 0x22]"
		script = "log \"//弓群技能ID，未激活时为0\""
		script = "log \"/*{p:$result}*/    int r_bow_gattack_id;\""
	strings:
		$pattern = { 81 F9 DE CD 9A 3B 72 ?? 85 C0 7C ?? 7F ?? 81 F9 E8 CD 9A 3B 76 ?? 8B 35 [4] 85 F6 74 ?? 83 BE [4] 00 74 ?? 8D 8D [4] E8 }
	condition:
		#pattern == 1
}

//42c8 int r_defend_times;
rule CRxPlayer_r_defend_times
{
	meta:
		script = "$result = [@pattern + 0x1c]"
		script = "log \"//对方正当防卫攻击剩余时间（该值比较可靠）\""
		script = "log \"/*{p:$result}*/    int r_defend_times;\""
	strings:
		$pattern = { 81 F9 41 9C 00 00 [2] 81 F9 A5 9C 00 00 [2] 85 C0 [2] 33 C9 39 4E ?? 57 8B B8 }
	condition:
		#pattern == 1
}

//492c RX_BILINK * r_poisonbuff;
//4930 int r_poisonnum;
rule CRxPlayer_r_poisonbuff
{
	meta:
		script = "$result = [@pattern + 0x05]"
		script = "log \"//中毒状态\""
		script = "log \"/*{p:$result}*/    RX_BILINK * r_poisonbuff;\""
		script = "$result = [@pattern + 0x10]"
		script = "log \"/*{p:$result}*/    int r_poisonnum;\""
	strings:
		$pattern = { 51 52 56 8D 8F [4] E8 [4] 8B 8F [4] BA 54 55 55 15 2B D1 83 FA 01 }
	condition:
		#pattern == 1
}



rule CRxPlayer_end
{
	meta:
		script = "log };"
		script = "log"
		script = "log"
	condition:
		true
}
