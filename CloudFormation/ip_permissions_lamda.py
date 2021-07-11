scratchList = []
  for rule in list(sg.ip_permissions):
    badRule = False
    if rule['FromPort'] in (80,443): continue
      for range in rule['IpRanges']:
        if range['CidIp'] == '0.0.0.0/0':
          bandRule = True
          break
    if badRule: scratchList.append(rule)
  if scratchList:
    non_compliant:sg.append(groupId)
    sg.revoke_ingress(IpPermissions = scratchList)
