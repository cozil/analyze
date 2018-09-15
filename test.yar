rule CRxApp_start
{
	meta:
		script = "log \"struct CRxApp {\""
		script = "$offset = 0x10"
		script = "msg \"Parsing CRxApp\""
	condition:
		true
}