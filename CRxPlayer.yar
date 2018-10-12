rule CRxPlayer_start
{
	meta:
		script = "Type.as CRxPlayer"
		script = "Type.aanc CRxPlayer,CRxObject"
		script = "Type.comment CRxPlayer,\"玩家对象管理\""
		script = "Type.ad CRxPlayer,\"void clear_move_state();\""
		script = "Type.ad CRxPlayer,\"bool is_poison_exists(uint32_t code) const;\""
		script = "Type.ad CRxPlayer,\"bool is_player_idle() const;\""
		script = "Type.ad CRxPlayer,\"bool is_player_rest() const;\""
		script = "Type.ad CRxPlayer,\"bool is_picking_herb() const;\""
		script = "Type.ad CRxPlayer,\"bool is_player_moving() const;\""
		script = "Type.ad CRxPlayer,\"bool is_farattack_career() const;\""
		script = "Type.ad CRxPlayer,\"void EnableJumpWall(bool enabled, uint32_t height);\""
		script = "Type.ad CRxPlayer,\"void clear_attack();\""
		
		script = "Type.ad CRxPlayer,\"bool is_career_knife() const {{ return (r_career == CareerKnife); }}\""
		script = "Type.ad CRxPlayer,\"bool is_career_sword() const {{ return (r_career == CareerSword); }}\""
		script = "Type.ad CRxPlayer,\"bool is_career_spear() const {{ return (r_career == CareerSpear); }}\""
		script = "Type.ad CRxPlayer,\"bool is_career_bow() const {{ return (r_career == CareerBow || r_career == CareerMnz); }}\""
		script = "Type.ad CRxPlayer,\"bool is_career_doctor() const {{ return (r_career == CareerDoctor); }}\""
		script = "Type.ad CRxPlayer,\"bool is_career_stabber() const {{ return (r_career == CareerStabber); }}\""
		script = "Type.ad CRxPlayer,\"bool is_career_musician() const {{ return (r_career == CareerMusician); }}\""
		script = "Type.ad CRxPlayer,\"bool is_career_hfg() const {{ return (r_career == CareerHfg); }}\""
		script = "Type.ad CRxPlayer,\"bool is_career_fister() const {{ return (r_career == CareerFister); }}\""
		script = "Type.ad CRxPlayer,\"bool is_career_mnz() const {{ return (r_career == CareerMnz); }}\""
		script = "Type.ad CRxPlayer,\"bool is_career_lfl() const {{ return (r_career == CareerLfl); }}\""
		
		script = "Type.ad CRxPlayer,\"bool is_flying_skill() const {{ return (r_light == 5 || r_light == 8); }}\""
		script = "Type.ad CRxPlayer,\"bool is_flying_state() const {{ return (r_light == 3 || r_light == 4); }}\""
		script = "Type.ad CRxPlayer,\"bool is_pet_rideon() const {{ return (r_pet_ride_flag > 0); }}\""
	condition:
		true
}

//014 int sessionid;
rule CRxPlayer_sessionid
{
	meta:
		script = "$result = byte:[@pattern + 0x02]"
		script = "Type.am CRxPlayer,int,sessionid,0,$result"
		script = "Type.mcomment CRxPlayer,sessionid,\"会话ID\""
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
		script = "Type.am CRxPlayer,char,r_name,0x30,$result\""
		script = "Type.mcomment CRxPlayer,r_name,\"角色名称\""
	strings:
		$pattern = { 81 F9 FF FF 00 00 [2] 8B 34 8D [4] 85 F6 [2] 83 7E 08 31 [2] 8D 56 ?? 52 8D 8F [4] E8 }
	condition:
		#pattern == 1
}

//019A uint16_t r_zdgroup;
rule CRxPlayer_r_zdgroup
{
	meta:
		script = "$result = [@pattern + 0x16]"
		script = "Type.am CRxPlayer,uint16_t,r_zdgroup,0,$result"
		script = "Type.mcomment CRxPlayer,r_zdgroup,\"真斗烈战、灵魂大战中区分敌友（不同为敌方）\""
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
		script = "Type.am CRxPlayer,CRxSkillItem*,r_skill_info,0,$result\""
		script = "Type.mcomment CRxPlayer,r_skill_info,\"正在使用的技能对象\""
	strings:
		$pattern = { 69 D2 50 1A 00 00 69 C0 90 01 00 00 8D BC 02 [4] 89 BE }
	condition:
		#pattern == 1
}

//200 uint32_t r_ani_id;
//204 uint32_t r_skillid;
rule CRxPlayer_r_ani_id
{
	meta:
		script = "$result = [@pattern + 0x09]"
		script = "Type.am CRxPlayer,uint32_t,r_ani_id,0,$result"
		script = "Type.mcomment CRxPlayer,r_ani_id,\"技能动作，置0即可屏蔽动画\""
		script = "$result = [@pattern + 0x1f]"
		script = "Type.am CRxPlayer,uint32_t,r_skillid,0,$result"
		script = "Type.mcomment CRxPlayer,r_skillid,\"最后一次使用的技能代码\""
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
		script = "Type.am CRxPlayer,short,r_select,0,$result"
		script = "Type.mcomment CRxPlayer,r_select,\"当前选中的对象编号\""
	strings:
		$pattern = { 6A 01 68 50 04 00 00 8B CE FF D2 8B 46 ?? 8B 0D [4] 89 81 [4] EB ?? C7 85 [4] FF FF 00 00 }
	condition:
		#pattern == 1
}

//1a50 Point3d r_destpos;
//1a68 short r_attack;
rule CRxPlayer_r_destpos
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "Type.am CRxPlayer,Point3d,r_destpos,0,$result"
		script = "Type.mcomment CRxPlayer,r_destpos,\"角色正在移动的目标位置\""
		script = "$result = [@pattern + 0x0e]"
		script = "Type.am CRxPlayer,short,r_attack,0,$result"
		script = "Type.mcomment CRxPlayer,r_attack,\"正在被攻击的怪物编号\""
	strings:
		$pattern = { 8D 87 [4] 89 85 [4] C7 87 [4] FF FF 00 00 C7 87 [4] 00 00 00 00 C6 87 [4] 00 C7 05 [4] 00 00 00 00 }
	condition:
		#pattern == 1
}

//1a6c uint32_t r_action;
//1a70 char r_state;
//1a74 int r_state2;
rule CRxPlayer_r_action
{
	meta:
		script = "$result = [@pattern + 0x0f]"
		script = "Type.am CRxPlayer,uint32_t,r_action,0,$result"
		script = "Type.mcomment CRxPlayer,r_action,\"状态(1-移动 2-平砍攻击 5:医平砍/技攻击/加辅助 6-打坐 7-采药\""
		script = "$result = [@pattern + 0x09]"
		script = "Type.am CRxPlayer,char,r_state,0,$result"
		script = "Type.mcomment CRxPlayer,r_state,\"活动状态,00-完全静止 01-移动中或正在攻击\""
		script = "$result = [@pattern + 0x36]"
		script = "Type.am CRxPlayer,int,r_state2,0,$result"
		script = "Type.mcomment CRxPlayer,r_state2,\"同上\""
	strings:
		$pattern = { 83 BE [4] FF 88 86 [4] C7 86 [4] 00 00 00 00 74 ?? 80 BE [4] 00 74 ?? C7 86 [4] 02 00 00 00 EB ?? 89 86 [4] C7 86 [4] 00 00 00 00 FF D7 }
	condition:
		#pattern == 1
}

//1a80 float r_attacklen;
//1a84 uint32_t r_next_skillid;
rule CRxPlayer_r_attacklen
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "Type.am CRxPlayer,float,r_attacklen,0,$result"
		script = "Type.mcomment CRxPlayer,r_attacklen,\"当前技能的攻击距离\""
		script = "$result = [@pattern + 0x0f]"
		script = "Type.am CRxPlayer,uint32_t,r_next_skillid,0,$result"
		script = "Type.mcomment CRxPlayer,r_next_skillid,\"下一个攻击技能id\""
	strings:
		$pattern = { D9 9F [4] 8B CF E8 [4] 81 BF [4] 51 C8 2D 00 75 ?? 8B 87 [4] 3D 25 C7 2D 00 }
	condition:
		#pattern == 1
}

//1c48 Point3d r_destpos2;
//1c84 Point3d r_currpos;
rule CRxPlayer_r_destpos2
{
	meta:
		script = "$result = [@pattern + 0x1d]"
		script = "Type.am CRxPlayer,Point3d,r_destpos2,0,$result"
		script = "Type.mcomment CRxPlayer,r_destpos2,\"必杀前调用移动函数使用的参数\""
		script = "$result = [@pattern + 0x23]"
		script = "Type.am CRxPlayer,Point3d,r_currpos,0,$result"
		script = "Type.mcomment CRxPlayer,r_currpos,\"玩家当前坐标\""
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
		script = "Type.am CRxPlayer,char,r_school,0x10,$result\""
		script = "Type.mcomment CRxPlayer,r_school,\"角色门派\""
	strings:
		$pattern = { 55 8B EC 56 [4] 8D 86 [4] 89 08 89 48 04 89 48 08 66 89 48 0C [4] 88 48 0E }
	condition:
		#pattern == 1
}

//2304 uint32_t r_pet_ride_flag;
rule CRxPlayer_r_pet_ride_flag
{
	meta:
		script = "$result = [@pattern + 0x0f]"
		script = "Type.am CRxPlayer,uint32_t,r_pet_ride_flag,0,$result"
		script = "Type.mcomment CRxPlayer,r_pet_ride_flag,\"宠物骑乘标记，0：没有骑乘，1：正在骑乘，大于1：已骑乘\""
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
		script = "Type.am CRxPlayer,int,r_shop_sid,0,$result"
		script = "Type.mcomment CRxPlayer,r_shop_sid,\"开店标识，等于sessionid时表示在开店状态\""
		script = "$result = [@pattern + 0x2b]"
		script = "Type.am CRxPlayer,char,r_shopname,0xf8,$result"
		script = "Type.mcomment CRxPlayer,r_shopname,\"开店名称\""
	strings:
		$pattern = { B9 03 00 00 00 F7 F9 B8 01 00 00 00 3B D0 75 ?? 83 BE [4] FF 88 86 [4] C7 86 [4] 00 00 00 00 74 ?? 80 BE [4] 00 74 ?? C7 86 [4] 02 00 00 00 }
	condition:
		#pattern == 1
}

//2408 uint32_t r_jumpflag;
rule CRxPlayer_r_jumpflag
{
	meta:
		script = "$result = [@pattern + 0x1a]"
		script = "Type.am CRxPlayer,uint32_t,r_jumpflag,0,$result"
		script = "Type.mcomment CRxPlayer,r_jumpflag,\"穿墙用，移动时调整为非0x0f值即可，否则遇到障碍物会停止前进\""
	strings:
		$pattern = { 8B 89 5C 4A 53 00 E8 [4] 80 BD [4] 01 0F 84 [4] 8B 97 [4] 8D B7 [4] 8B CE 89 95 [4] E8 }
	condition:
		#pattern == 1
}

//263c uint32_t r_light;
rule CRxPlayer_r_light
{
	meta:
		script = "$result = [@pattern + 0x07]"
		script = "Type.am CRxPlayer,uint32_t,r_light,0,$result"
		script = "Type.mcomment CRxPlayer,r_light,\"轻功标志 1:15轻功疾风御气术 2:60轻功梯云纵 3/4:飞行状态 5:100轻功草上飞 6:疾龙一式 7:疾龙二式 8:疾龙三式\""
	strings:
		$pattern = { E8 [4] 8B 83 [4] 83 F8 03 74 ?? 83 F8 04 74 ?? 83 F8 08 74 ?? 83 F8 09 }
	condition:
		#pattern == 1
}

//2688 uint32_t r_run;
rule CRxPlayer_r_run
{
	meta:
		script = "$result = [@pattern + 0x28]"
		script = "Type.am CRxPlayer,uint32_t,r_run,0,$result"
		script = "Type.mcomment CRxPlayer,r_run,\"当r_light==0时, 0:表示行走 1:表示跑\""
	strings:
		$pattern = { 3D 7A 90 06 00 [16] 81 E9 14 90 06 00 [11] 8B 86 }
	condition:
		#pattern == 1
}

//26c4 uint32_t r_visible;
rule CRxPlayer_r_visible
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "Type.am CRxPlayer,uint32_t,r_visible,0,$result"
		script = "Type.mcomment CRxPlayer,r_visible,\"玩家是否在场景中显示\""
	strings:
		$pattern = { 89 81 [4] B9 01 00 00 00 33 D2 A1 [4] 3D 29 23 00 00 [2] 3D 8D 23 00 00 [2] 3D F1 23 00 00 }
	condition:
		#pattern == 1
}

//26fc uint32_t r_career;
rule CRxPlayer_r_career
{
	meta:
		script = "$result = [@pattern + 0x18]"
		script = "Type.am CRxPlayer,uint32_t,r_career,0,$result"
		script = "Type.mcomment CRxPlayer,r_career,\"玩家职业，与CRxRoleInfo中的career值不一定相同\""
	strings:
		$pattern = { 83 7E 08 31 0F 85 [4] 8B 4E ?? 3B 4F ?? 0F 84 [4] 83 BE [4] 06 0F 85 [4] 80 BE [4] 00 }
	condition:
		#pattern == 1
}

//2700 uint32_t r_sex;
rule CRxPlayer_r_sex
{
	meta:
		script = "$result = [@pattern + 0x16]"
		script = "Type.am CRxPlayer,uint32_t,r_sex,0,$result"
		script = "Type.mcomment CRxPlayer,r_sex,\"玩家性别\""
	strings:
		$pattern = { 83 F8 76 [2] 83 F8 77 [2] 83 F8 02 [2] BA 01 00 00 00 39 93 }
	condition:
		#pattern == 1
}

//2778 uint32_t r_deadstate;
//与CRxPlayer_r_destpos相同
rule CRxPlayer_r_deadstate
{
	meta:
		script = "$result = [@pattern + 0x33]"
		script = "Type.am CRxPlayer,uint32_t,r_deadstate,0,$result"
		script = "Type.mcomment CRxPlayer,r_deadstate,\"人物死亡状态，死亡时置2\""
	strings:
		$pattern = { 8D 87 [4] 89 85 [4] C7 87 [4] FF FF 00 00 C7 87 [4] 00 00 00 00 C6 87 [4] 00 C7 05 [4] 00 00 00 00 }
		//offset:0x17
		//$pattern = { 6A 01 68 50 04 00 00 8B CE FF D0 B8 01 00 00 00 E9 [4] 8B 87 [4] DD D8 }
	condition:
		#pattern == 1
}

//33f0 uint32_t r_move_flag1;
//33f4 uint32_t r_move_flag2;
rule CRxPlayer_move_flag
{
	meta:
		script = "$result = [@pattern + 0x0a]"
		script = "Type.am CRxPlayer,uint32_t,r_move_flag1,0,$result"
		script = "Type.mcomment CRxPlayer,r_move_flag1,\"两个标记为0时表示人物正在移动，瞬移使用，瞬移后置1\""
		script = "$result = [@pattern + 0x04]"
		script = "Type.am CRxPlayer,uint32_t,r_move_flag2,0,$result"
	strings:
		$pattern = { 33 C9 89 8F [4] 89 8F [4] C7 87 [4] 01 00 00 00 8B 87 [4] 3B C1 0F 84 [4] 8B 40 ?? 81 C7 68 1A 00 00 57 6A 1E }
	condition:
		#pattern == 1
}

//3408 uint32_t r_selected_flag;
rule CRxPlayer_r_selected_flag
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "Type.am CRxPlayer,uint32_t,r_selected_flag,0,$result"
		script = "Type.mcomment CRxPlayer,r_selected_flag,\"点击角色选中标记\""
	strings:
		$pattern = { 8B 88 [8] 80 BE [4] 00 [2] C7 85 [4] 80 00 00 00 [6] C7 85 [4] 00 08 00 00 }
	condition:
		#pattern == 1
}

//4298 uint32_t r_bow_gattack_id;
rule CRxPlayer_r_bow_gattack_id
{
	meta:
		script = "$result = [@pattern + 0x22]"
		script = "Type.am CRxPlayer,uint32_t,r_bow_gattack_id,0,$result"
		script = "Type.mcomment CRxPlayer,r_bow_gattack_id,\"弓群技能ID，未激活时为0\""
	strings:
		$pattern = { 81 F9 DE CD 9A 3B 72 ?? 85 C0 7C ?? 7F ?? 81 F9 E8 CD 9A 3B 76 ?? 8B 35 [4] 85 F6 74 ?? 83 BE [4] 00 74 ?? 8D 8D [4] E8 }
	condition:
		#pattern == 1
}

//42c8 uint32_t r_defend_times;
rule CRxPlayer_r_defend_times
{
	meta:
		script = "$result = [@pattern + 0x1c]"
		script = "Type.am CRxPlayer,uint32_t,r_defend_times,0,$result"
		script = "Type.mcomment CRxPlayer,r_defend_times,\"对方正当防卫攻击剩余时间（该值比较可靠）\""
	strings:
		$pattern = { 81 F9 41 9C 00 00 [2] 81 F9 A5 9C 00 00 [2] 85 C0 [2] 33 C9 39 4E ?? 57 8B B8 }
	condition:
		#pattern == 1
}

//492c RX_BILINK * r_poisonbuff;
//4930 uint32_t r_poisonnum;
rule CRxPlayer_r_poisonbuff
{
	meta:
		script = "$result = [@pattern + 0x05]"
		script = "Type.am CRxPlayer,RX_BILINK*,r_poisonbuff,0,$result"
		script = "Type.mcomment CRxPlayer,r_poisonbuff,\"中毒状态\""
		script = "$result = [@pattern + 0x10]"
		script = "Type.am CRxPlayer,uint32_t,r_poisonnum,0,$result"
	strings:
		$pattern = { 51 52 56 8D 8F [4] E8 [4] 8B 8F [4] BA 54 55 55 15 2B D1 83 FA 01 }
	condition:
		#pattern == 1
}

rule CRxPlayer_end
{
	meta:
		script = "Type.print CRxPlayer,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}
