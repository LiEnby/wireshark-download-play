-- Opcode on :10
dlplay = Proto("DSDOWNLOADPLAY", "Nintendo DS Download Play")

-- opcode
local t_magic = ProtoField.uint8("dlplay.magic", "Magic", base.HEX)
local t_flag = ProtoField.uint8("dlplay.flag", "Flag", base.DEC)
local t_port = ProtoField.uint8("dlplay.port", "Port", base.DEC)
local t_opcode = ProtoField.uint8("dlplay.opcode", "Opcode", base.HEX)
local t_seq = ProtoField.uint8("dlplay.seq", "Sequence", base.DEC)

-- get name packet
local t_bytelen = ProtoField.uint8("dlplay.bytelen", "Name Length (bytes)", base.HEX)
local t_strlen = ProtoField.uint8("dlplay.strlen", "Name Length (characters)", base.HEX)
local t_name = ProtoField.string("dlplay.name", "Name", base.UNICODE)

-- get nds rom packet
local t_offset = ProtoField.uint16("dlplay.offset", "Offset", base.HEX)

-- keepalive form
local t_random = ProtoField.uint32("dlplay.random", "Random", base.HEX)



dlplay.fields = {
    t_magic, t_flag, t_port, t_opcode, t_seq, -- opcode packet general
	t_bytelen, t_strlen, t_name, -- GET_DS_NAME packet
	t_offset, -- GET_NDS_ROM
	t_random, -- keepalive form
}

g_opcodes = {
	GET_INFO = 0x00,
	GET_DS_NAME = 0x07,
	GET_RSA = 0x08,
	GET_NDS_ROM = 0x9
}

local function get_opcode_name(opcode)

	for key, value in pairs(g_opcodes) do
		if value == opcode then
			return key
		end
	end

	return "UNKNOWN_OPCODE"

end


local function set_ds_play_header(buffer, pinfo, tree, method)
	local subtree = tree:add(dlplay, buffer(), dlplay.description .. " - " .. method)

	pinfo.cols.protocol = dlplay.name
	pinfo.cols.info = dlplay.description .. ": " .. method
	
	return subtree
	
end


local function parse_opcode(buffer, pinfo, tree)
	
	if buffer(0,2):le_uint() == 0x8000 then
		local subtree = set_ds_play_header(buffer, pinfo, tree, "Keep Alive (DS)")
		Dissector.get("data"):call(buffer,pinfo,subtree)
		return true
	end
	
	local v_magic = buffer(0, 1)
	local magic = v_magic:le_uint()

	-- check magic number	
	if magic ~= 0x04 then
		return false
	end

	local v_port = buffer(1, 1)
	local flag = (v_port:le_uint() >> 4)
	local port = v_port:le_uint() & 0x0F

	local v_opcode = buffer(2, 1)
	local opcode = v_opcode:le_uint()

	local v_index = buffer(3, 1)
	local index = v_index:le_uint()
	local opcode_name = get_opcode_name(opcode)

	local v_data = buffer(4)

	local length = buffer:len()
	local subtree = set_ds_play_header(buffer, pinfo, tree, opcode_name)
	
	
	pinfo.columns["info"]:append(" op:" .. opcode)
	pinfo.columns["info"]:append(" seq:" .. index)

	
	subtree:add_le(t_magic, v_magic)
	
	if flag ~= 0 then
		subtree:add_le(t_flag, v_port, flag)
	end
	subtree:add_le(t_port, v_port, port)

	subtree:add_le(t_opcode, v_opcode, opcode )
	subtree:add_le(t_seq, v_index, index)
	
	if opcode == g_opcodes.GET_DS_NAME then
		
		if index == 0 then

			local v_bytelen = v_data(4,1)
			local v_strlen = v_data(5,1)
			
			local strlen = v_strlen:le_uint()
			local bytelen = v_bytelen:le_uint()
			
			subtree:add(t_strlen, v_strlen, strlen)			
			subtree:add(t_bytelen, v_bytelen, bytelen)			
			
			pinfo.columns["info"]:append(" strlen:" .. strlen)
			pinfo.columns["info"]:append(" bytelen:" .. bytelen)

		else
			local name = v_data:le_ustring()
			subtree:add(t_name, v_data, name)			
			pinfo.columns["info"]:append(" data:" .. name)

		end
	elseif opcode == g_opcodes.GET_NDS_ROM then
		local v_offset = v_data(0,2)
		local offset = v_offset:uint()
		
		subtree:add(t_offset, v_offset, offset)	
		
		pinfo.columns["info"]:append(" offset:" .. offset)
		
	else
		Dissector.get("data"):call(v_data:tvb(),pinfo,subtree)
	end
	
	return true
end

local function parse_response(buffer, pinfo, tree)
	local length = buffer:len()	
	local subtree = set_ds_play_header(buffer, pinfo, tree, "Response")	

	Dissector.get("data"):call(buffer,pinfo,subtree)
	return true
end

local function parse_keepalive(buffer, pinfo, tree)
	local length = buffer:len()	
	local subtree = set_ds_play_header(buffer, pinfo, tree, "Keep Alive (Station)")	
	
    subtree:add(t_random, buffer(0, 4))
	return true
end 

function  dlplay.dissector(buffer, pinfo, tree)
	local keepalive = Address.ether("03:09:bf:00:00:03")
	local opcode = Address.ether("03:09:bf:00:00:10")
	local response = Address.ether("03:09:bf:00:00:00")
	
	-- cant figure out how to compare them properly
	if tostring(pinfo.dst) == tostring(keepalive) then
		-- parse keepalive
		return parse_keepalive(buffer, pinfo, tree)
	end
	if tostring(pinfo.dst) == tostring(opcode) then
		-- parse t_opcode
		return parse_opcode(buffer, pinfo, tree)
	end
	if tostring(pinfo.dst) == tostring(response) then
		-- parse response
		return parse_response(buffer, pinfo, tree)
	end
	
	return false
end

dlplay:register_heuristic("wlan_data", dlplay.dissector)