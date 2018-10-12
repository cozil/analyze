rule CRxNpc_start
{
	meta:
		script = "Type.as CRxNpc"
		script = "Type.aanc CRxNpc,CRxObject"
		script = "Type.comment CRxNpc,\"游戏NPC/怪物对象管理\""
		script = "$offset = 0"
		script = "Type.ad CRxNpc,\"bool attack_state_intime(uint32_t dwIntvl = 5000) const;\""
		script = "Type.ad CRxNpc,\"bool attack_not_me() const;\""
		script = "Type.ad CRxNpc,\"bool attack_me() const;\""
		script = "Type.ad CRxNpc,\"bool attack_teamate() const;\""
		script = "Type.ad CRxNpc,\"void clear_my_flags();\""
		
		script = "Type.ad CRxNpc,\"bool is_valid_npc() const;\""
		script = "Type.ad CRxNpc,\"bool is_valid_monster() const;\""
		script = "Type.ad CRxNpc,\"bool is_super_monster() const;\""
		script = "Type.ad CRxNpc,\"bool is_valid_herb() const;\""
		script = "Type.ad CRxNpc,\"bool is_fy_monster() const;\""
		script = "Type.ad CRxNpc,\"uint32_t get_xlife_ratio() const;\""
		script = "Type.ad CRxNpc,\"bool check_monster_pos() const;\""
	condition:
		true
}

//对象指针位移
//与x_monflag的特征码相同
rule CRxNpc_offset__
{
	meta:		
		script = "$offset = 0x100 - byte:[@pattern + 0x02]"
		script = "Type.comment CRxNpc,\"对象指针位移可能是：{d:-$offset}，部分成员偏移需要减去该值\""
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
		script = "Type.am CRxNpc,int,sessionid,0,$result"
		script = "Type.mcomment CRxNpc,sessionid,\"NPC会话ID -{d:$offset}\""
	strings:
		$pattern = { 3D 81 0C 00 00 [2] 3D 59 1B 00 00 [2] 3D BD 1B 00 00 [2] C7 83 [4] 07 00 00 00 5B 8B E5 5D C3 8B 43 }
	condition:
		#pattern == 1	
}

//354 uint32_t x_showblood;
rule CRxNpc_x_showblood
{
	meta:
		script = "$result = [@pattern + 0x13]"
		script = "Type.am CRxNpc,uint32_t,x_showblood,0,$result"
		script = "Type.mcomment CRxNpc,x_showblood,\"显示怪物血条\""
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
		script = "Type.am CRxNpc,float,x_distance,0,$result"
		script = "Type.mcomment CRxNpc,x_distance,\"怪物与玩家直线距离\""
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
		script = "Type.am CRxNpc,char,x_name,0x20,$result"
		script = "Type.mcomment CRxNpc,x_name,\"怪物名称 -{d:$offset}\""
		
		//自定义变量
		script = "$result += 0x21"
		script = "Type.am CRxNpc,uint8_t,ux_superflag,0,$result"
		script = "Type.mcomment CRxNpc,ux_superflag,\"自定：被连击招式攻击标记\""
		
		script = "Type.am CRxNpc,uint8_t,ux_selmon"
		script = "Type.mcomment CRxNpc,ux_selmon,\"自定：引怪时被选定的怪物标志\""	
		
		script = "Type.am CRxNpc,uint8_t,ux_attackwho"
		script = "Type.mcomment CRxNpc,ux_attackwho,\"自定：攻击目标 1-自己，2-队友，3-别人\""	
		
		script = "Type.am CRxNpc,uint32_t,ux_lastattack"
		script = "Type.mcomment CRxNpc,ux_lastattack,\"自定：上一次怪物攻击自己的时间\""	
		
		script = "Type.am CRxNpc,uint32_t,ux_seltime"
		script = "Type.mcomment CRxNpc,ux_seltime,\"自定：上次选择时间, PK模式用于保存屏蔽到时间值\""

		script = "Type.am CRxNpc,float,unused_float"
		
		script = "Type.am CRxNpc,uint32_t,ux_lasttesttime"
		script = "Type.mcomment CRxNpc,ux_lasttesttime,\"自定：上次检测距离的时间\""
	
		script = "Type.am CRxNpc,uint8_t,ux_failnum"
		script = "Type.mcomment CRxNpc,ux_failnum,\"自定：攻击失败更换次数（达到3次时永久不选择）\""	
	strings:
		$pattern = { 8D 9F [4] 85 DB 0F 84 [4] A1 [4] 8B 10 6A 00 6A 1C 50 8B 82 [4] FF D0 }
	condition:
		#pattern == 1	
}

//3B0 uint32_t x_monflag;
//与CRxNpc_x_showblood的特征码相同
rule CRxNpc_x_monflag
{
	meta:		
		script = "$result = [@pattern + 0x1f]"
		script = "Type.am CRxNpc,uint32_t,x_monflag,0,$result"
		script = "Type.mcomment CRxNpc,x_monflag,\"0x2710或以上的值为怪物,否则为NPC\""
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
		script = "Type.am CRxNpc,short,x_attack,0,$result"
		script = "Type.mcomment CRxNpc,x_attack,\"怪物正在攻击的玩家编号 -{d:$offset}\""
	strings:
		$pattern = { 6A 01 50 6A 1C 8B CE E8 [4] 85 C0 0F 84 [4] 8B 46 ?? 3B C3 74 ?? 89 86 }
	condition:
		#pattern == 1	
}

//3B8 uint32_t x_visible;
rule CRxNpc_x_visible
{
	meta:		
		script = "$result = [@pattern + 0x16]"
		script = "Type.am CRxNpc,uint32_t,x_visible,0,$result"
		script = "Type.mcomment CRxNpc,x_visible,\"怪物是否可见\""
	strings:
		$pattern = { 6A 00 68 [4] 68 61 04 00 00 FF D2 8B 8D [4] 89 81 }
	condition:
		#pattern == 1	
}

//3BC uint32_t x_deadstatus;
//3C0 uint32_t x_dead;
rule CRxNpc_x_dead
{
	meta:
		script = "$result = [@pattern + 0x11] - $offset"
		script = "Type.am CRxNpc,uint32_t,x_deadstatus,0,$result"
		script = "Type.mcomment CRxNpc,x_deadstatus,\"怪物死亡状态变化 -{d:$offset}\""
		script = "$result = [@pattern + 0x1b] - $offset"
		script = "Type.am CRxNpc,uint32_t,x_dead,0,$result"
		script = "Type.mcomment CRxNpc,x_dead,\"怪物死亡标志 -{d:$offset}\""
	strings:
		$pattern = { D9 E8 33 DB D9 9E [4] B8 FF FF 00 00 C7 86 [4] 02 00 00 00 C7 86 [4] 01 00 00 00 }
	condition:
		#pattern == 1
}

//3C8 uint32_t x_shootdown;
//3CC uint32_t x_shoottime;
rule CRxNpc_x_shoot
{
	meta:
		script = "$result = [@pattern + 0x2d]"
		script = "Type.am CRxNpc,uint32_t,x_shootdown,0,$result"
		script = "Type.mcomment CRxNpc,x_shootdown,\"绝命技能可以使用标志\""
		script = "$result = [@pattern + 0x27]"
		script = "Type.am CRxNpc,uint32_t,x_shoottime,0,$result"
		script = "Type.mcomment CRxNpc,x_shoottime,\"绝命技施放前开始计时\""
	strings:
		$pattern = { 3D 32 3C 00 00 [2] 3D 34 3C 00 00 [2] 3D 30 3F 00 00 [2] C7 86 [4] 01 00 00 00 8B 86 [4] 89 BE [4] 89 BE }
	condition:
		#pattern == 1
}

//5F4 uint32_t x_life;
//5F8 uint32_t x_grade;
rule CRxNpc_x_life
{
	meta:
		script = "$result = [@pattern + 0x02] - $offset"
		script = "Type.am CRxNpc,uint32_t,x_life,0,$result"
		script = "Type.mcomment CRxNpc,x_life,\"怪物当前血值 -{d:$offset}\""
		script = "$result = [@pattern + 0x26] - $offset"
		script = "Type.am CRxNpc,uint32_t,x_grade,0,$result"
		script = "Type.mcomment CRxNpc,x_grade,\"怪物等级 -{d:$offset}\""
	strings:
		$pattern = { C7 86 [4] 00 00 00 00 81 3D [4] 29 A0 00 00 [2] 81 BE [4] 72 3F 00 00 0F BF 41 ?? 89 86 }
	condition:
		#pattern == 1
}

//610 uint32_t x_maxlife;
rule CRxNpc_x_maxlife
{
	meta:
		script = "$result = [@pattern + 0x0f] - $offset"
		script = "Type.am CRxNpc,uint32_t,x_maxlife,0,$result"
		script = "Type.mcomment CRxNpc,x_maxlife,\"怪物最大血值 -{d:$offset}\""
	strings:
		$pattern = { C7 86 [4] 00 00 00 00 8B 41 ?? 89 86 [4] 8B 86 [4] 3B 41 [28] 81 3D [4] 29 A0 00 00 }
	condition:
		#pattern == 1
}

//280 _mons_pos::pos
rule CRxNpc_mons_pos
{
	meta:
		script = "Type.as _MONS_POS"
		script = "$result = [@pattern + 0x13]"
		script = "Type.am _MONS_POS,Point3d,pos,0,$result"
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
		script = "Type.am CRxNpc,_MONS_POS*,x_pMpos,0,$result"
		script = "Type.mcomment CRxNpc,x_pMpos,\"怪物坐标指针\""
	strings:
		$pattern = { 8B B6 [4] 85 D2 [40] 81 C1 10 FC FF FF 81 F9 8F 00 00 00 }
	condition:
		#pattern == 1
}

//1428 uint32_t x_poison_num;
rule CRxNpc_x_poison_num
{
	meta:
		script = "$result = [@pattern + 0x09] - $offset"
		script = "Type.am CRxNpc,uint32_t,x_poison_num,0,$result"
		script = "Type.mcomment CRxNpc,x_poison_num,\"怪物中毒数量（CK技能中毒数量）-{d:$offset}\""
	strings:
		$pattern = { C7 45 ?? 00 00 FF FF 89 BE [4] 39 BE [4] 74 ?? 68 10 01 00 00 }
	condition:
		#pattern == 1
}

//1A18 uint32_t x_group;
rule CRxNpc_x_group
{
	meta:
		script = "$result = [@pattern + 0x0d]"
		script = "Type.am CRxNpc,uint32_t,x_group,0,$result"
		script = "Type.mcomment CRxNpc,x_group,\"风云神物的势力状态，只有monflag = 3c0b 时才能使用\""
	strings:
		$pattern = { 81 F9 0B 3C 00 00 75 ?? 0F B6 D0 3B 96 [6] B8 05 00 00 00 E9 [4] 81 F9 5E 3C 00 00 0F 8C [4] 81 F9 6E 3C 00 00 0F 8F [4] 81 F9 60 3C 00 00 }
	condition:
		#pattern == 1
}

rule CRxNpc_end
{
	meta:
		script = "Type.print _MONS_POS,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
		script = "Type.print CRxNpc,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}
