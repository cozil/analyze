rule CRxPet_start
{
	meta:
		script = "Type.as CRxPet"
		script = "Type.comment CRxPet,\"玩家操控的宠物属性结构\""
		script = "Type.am CRxPet,char,name,0x14"
		script = "Type.mcomment CRxPet,name,\"宠物名称\""
		
		script = "Type.ad CRxPet,\"int get_affability_percent() const;\""
		script = "Type.ad CRxPet,\"bool is_valid() const;\""
		script = "Type.ad CRxPet,\"bool is_rideable() const;\""
	condition:
		true
}

//0014 uint8_t job
rule CRxPet_job
{
	meta:
		script = "$result = [@pattern + 0x14]"
		script = "lblset $result,CRxPet::job"
		script = "Type.am CRxPet,uint8_t,job,0,$result - PetInfo"
		script = "Type.mcomment CRxPet,name,\"宠物转职次数\""		
	strings:
		$pattern = { 83 C1 06 89 4D ?? 3C 05 [2] C7 45 ?? 0F 00 00 00 0F BE 0D }
	condition:
		#pattern == 1
}

//0015 uint8_t type
rule CRxPet_type
{
	meta:
		script = "$result = [@pattern + 0x1]"
		script = "lblset $result,CRxPet::type"
		script = "Type.am CRxPet,uint8_t,type,0,$result - PetInfo"
		script = "Type.mcomment CRxPet,type,\"宠物类型 01 - 猫  02 - 雕  03 - 豹  04 - 虎 05 - 雪狼\""
	strings:
		$pattern = { A0 [4] 0F BE C8 83 C1 06 89 4D ?? 3C 05 }
	condition:
		#pattern == 1
}

//0248 uint32_t affability;
//024c uint32_t maxAffability;
rule CRxPet_affability
{
	meta:
		script = "$result = [@pattern + 0x4]"
		script = "lblset $result,CRxPet::affability"
		script = "Type.am CRxPet,uint32_t,affability,0,$result - PetInfo"
		script = "Type.mcomment CRxPet,affability,\"忠诚度\""
		
		script = "$result = [@pattern + 0xd]"
		script = "lblset $result,CRxPet::maxAffability"
		script = "Type.am CRxPet,uint32_t,maxAffability,0,$result - PetInfo"		
	strings:
		$pattern = { 8B 46 06 A3 [4] 8B 4E 0A 89 0D [4] 5E 5D C2 04 00 }
	condition:
		#pattern == 1
}

//268 uint16_t grade;
rule CRxPet_grade
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "lblset $result,CRxPet::grade"
		script = "Type.am CRxPet,uint16_t,grade,0,$result - PetInfo"
		script = "Type.mcomment CRxPet,grade,\"宠物等级\""
	strings:
		$pattern = { 66 A3 [4] 8D 87 [4] 99 6A 00 2B C2 D1 F8 6A 31 50 E8 }
	condition:
		#pattern == 1
}

rule CRxPet_end
{
	meta:
		script = "Type.print CRxPet,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}