rule CRxSkillList_start
{
	meta:
		script = "Type.as CRxSkillItem"
		script = "Type.comment CRxSkillItem,\"技能数据(static)\n目前仅使用了skill_id和attach_length两个成员\n只要结构大小不变则不需要手工重新分析\""
		script = "Type.am CRxSkillItem,int,skill_id,0,0"
		script = "Type.am CRxSkillItem,char,name,0x40,4"
		script = "Type.am CRxSkillItem,short,grade,0,0x48"
		script = "Type.am CRxSkillItem,short,job,0,0x4a"
		script = "Type.am CRxSkillItem,int,attack_length,0,0x54"
		script = "Type.am CRxSkillItem,int,cooldown_time,0,0x58"
		script = "Type.am CRxSkillItem,char,type,0,0x61"
		script = "Type.am CRxSkillItem,int,ani_id,0,0x62"
		script = "Type.am CRxSkillItem,char,desc,0x128,0x68"
		script = "Type.as CRxSkillList"
		script = "Type.am CRxSkillList,int,skill_id,0,0"
		script = "Type.am CRxSkillList,char,name,0x10,4"
		script = "Type.am CRxSkillList,char,group,0,0x45"
		script = "Type.am CRxSkillList,char,career,0,0x46"
		script = "Type.am CRxSkillList,char,grade,0,0x48"
		script = "Type.am CRxSkillList,char,job,0,0x4a"
		script = "Type.am CRxSkillList,CRxSkillItem,items,0x10,0x150"
		script = "$result = [@pattern + 0x2]"
		script = "Type.ad CRxSkillList,\"const static int MaxSkillCount = 0x{$result};\""
		script = "$result1 = [@pattern + 0x10]"
		script = "Type.size CRxSkillList"
		script = "cmp $result,$result1"
		script = "jnz _FAIL"
		script = "Type.print CRxSkillItem,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
		script = "Type.print CRxSkillList,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
		script = "jmp _EXIT"
		script = "_FAIL:"
		script = "log \"Size of CRxSkillList has changed to 0x{$result1}\""
		script = "_EXIT:"
	strings:
		$pattern = { 81 FF [4] 0F 8D [4] 8B CF 69 C9 [4] 8B B1 [4] 8D 99 [12] 14 FA 1E 00 [8] 78 FA 1E 00 [8] DC FA 1E 00 }
	condition:
		#pattern == 1
}
