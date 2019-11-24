from django import template

register = template.Library()

@register.filter(name='get_key_val')
def get_key_value(mydict, key):
    return mydict[key]

@register.filter(name='get_risk')
def get_risk(mydict, key):
    return mydict[key]["risk"]

@register.filter(name='get_name')
def get_name(mydict, key):
    return mydict[key]["name"]

@register.filter(name='get_count')
def get_count(mydict, key):
    return mydict[key]["count"]


@register.filter(name='get_critical_count')
def get_critical_count(mydict, key):
    return mydict[key]["Critical"]

@register.filter(name='get_high_count')
def get_high_count(mydict, key):
    return mydict[key]["High"]

@register.filter(name='get_medium_count')
def get_medium_count(mydict, key):
    return mydict[key]["Medium"]

@register.filter(name='get_low_count')
def get_low_count(mydict, key):
    return mydict[key]["Low"]

@register.filter(name='get_info_count')
def get_info_count(mydict, key):
    return mydict[key]["Info"]
