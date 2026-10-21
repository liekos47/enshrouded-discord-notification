#!/usr/bin/env python3
"""Build watcher/killers.json: killer guid (the `killer=` of a death line) -> readable name.

The mod's killer guid is the guid of a keen::ecs::TemplateResource: the template of the enemy,
projectile, explosion or trap that dealt the killing blow. Every template carries its internal name
("Enemy_Fogger_Depleted_Spear"), read here from the server's enshrouded_server.kfc and
.kfc_resources. The server ships no localization, so the readable names come from RULES below.

usage: make_killers.py <dir with enshrouded_server.kfc> [out.json]   (Python 3.14+: compression.zstd)

Container layout from Brabb3l/kfc-parser (crates/kfc-base/src/container/header.rs).
"""
import json
import re
import struct
import sys
from compression import zstd

TEMPLATE_RESOURCE = 0x39768775   # type hash of keen::ecs::TemplateResource (server 1.0 / 1.0.0.2)


def read_templates(base):
    """{guid text: internal name} for every TemplateResource in <base>.kfc / .kfc_resources."""
    d = open(base + ".kfc", "rb").read()
    if d[:4] != b"KFC4":
        sys.exit(f"{base}.kfc: not a KFC4 file")

    def loc(i):   # KFCLocation i after the 16-byte header start: offset relative to the field
        fo = 0x10 + 8 * i
        off, count = struct.unpack_from("<II", d, fo)
        return fo + off, count

    keys, n = loc(10)       # resource_keys: guid[16], type hash u32, part[12]
    values, _ = loc(11)     # resource_values: offset u32, size u32 (in the uncompressed stream)
    chunks_at, n_chunks = loc(15)   # chunk: offset, size, compressed size, uncompressed offset, size
    chunks = [struct.unpack_from("<5I", d, chunks_at + 20 * i) for i in range(n_chunks)]
    cache = {}
    res = open(base + ".kfc_resources", "rb")

    def read(off, size):
        out = b""
        for i, (coff, _, csize, uoff, usize) in enumerate(chunks):
            if uoff + usize <= off or uoff >= off + size:
                continue
            if i not in cache:
                res.seek(coff)
                cache[i] = zstd.decompress(res.read(csize))
            out += cache[i][max(off, uoff) - uoff:min(off + size, uoff + usize) - uoff]
        return out

    out = {}
    for i in range(n):
        raw = d[keys + 32 * i:keys + 32 * i + 32]
        if struct.unpack_from("<I", raw, 16)[0] != TEMPLATE_RESOURCE:
            continue
        off, size = struct.unpack_from("<II", d, values + 8 * i)
        b = read(off, size)
        name_off, name_len = struct.unpack_from("<II", b, 0)   # relative pointer + length at +0
        h = raw[:16].hex()   # 8-4-4-4-12 of the bytes in memory order, as the mod prints it
        out[f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"] = \
            b[name_off:name_off + name_len].decode("utf-8", "replace")
    return out


# First match wins, searched anywhere in the internal name (case-insensitive), so a projectile,
# explosion or attack of a creature gets that creature's name. Internal names: Fogger/Fog = the
# Fell, Skeleton = the Hollow, Lizardpeople = the Drak. Names are a reading of the internal ones,
# not the game's localized text: the config's "killers" map overrides any of them.
RULES = [
    # Player-made: spells, companions, fireworks
    (r"^(Player|Projectile_Player|Explosion_Player|Attack_Player|Projectile_Companion|"
     r"Explosion_Companion|Attack_Companion|Enemy_Companion)", "another player"),
    # Bosses
    (r"Vorgoth", "Vorgoth"),
    (r"MysterTraveler", "the Mysterious Traveler"),
    (r"Fog_?Dragon", "the Fell Wispwyvern"),
    (r"SkeletonGiantLizard", "a Hollow Giant Lizard"),
    (r"GiantLizard", "a Giant Lizard"),
    (r"CritterQueen", "a Critter Queen"),
    (r"Fog(ger)?_Predator", "a Fell Predator"),
    (r"Monstrosity", "a Fell Monstrosity"),
    (r"Skeleton_Hero|SkeletonHero|Skeleton_Heavy_Hero", "a Hollow Hero"),
    (r"Vukah_Bigfoot|Midboss_Vukah", "a Vukah Brawler"),
    (r"Vukah.*Hive_Tyrant", "a Vukah Hive Tyrant"),
    # Ancient constructs (internal names misspell it: AncienctConstruct, AncienctConstrcut)
    (r"Ancien\w*Critter", "an Ancient Spider"),
    (r"Ancien\w*?Constr\w*?_Heavy", "an Ancient Colossus"),
    (r"Modular0?1_Grunt", "an Ancient Grunt"),
    (r"FireRoller", "an Ancient Fire Roller"),
    (r"Modular03_Siren", "an Ancient Siren"),
    (r"Modular04_Bull", "an Ancient Bull"),
    (r"Modular05_Bouncer", "an Ancient Bouncer"),
    (r"Modular06a|_Sentry", "an Ancient Sentry"),
    (r"Modular06b|_Burner", "an Ancient Burner"),
    (r"Modular06c|Shortie", "an Ancient Shortie"),
    (r"Modular07|_Dozer", "an Ancient Dozer"),
    (r"Modular08|_Weaver", "an Ancient Weaver"),
    (r"Modular09|_Beacon", "an Ancient Beacon"),
    (r"Modular10|_Slicer", "an Ancient Slicer"),
    (r"Ancien\w*?(Constr|Modular)", "an Ancient Construct"),
    # Drak (lizard people)
    (r"Lizard(people)?Drak00|Lizardpeople.*(Weakling|Skink)", "a Drak Skink"),
    (r"Lizard(people)?Drak01|Lizardpeople.*Spear", "a Drak Spearman"),
    (r"Lizard(people)?Drak02|Lizardpeople.*(Ranger|Chakram)", "a Drak Ranger"),
    (r"Lizard(people)?Drak03|Lizardpeople.*Elite", "a Drak Elite"),
    (r"Lizard(people)?Drak04|Lizardpeople.*(Mage|Staff)", "a Drak Mage"),
    (r"Lizard(people)?Drak05|Lizard(people)?_Heavy|Lizardpeople.*Mace", "a Drak Brute"),
    (r"Lizardpeople", "a Drak"),
    # The Fell
    (r"Black_Knight", "a Fell Knight"),
    (r"Banshee", "a Fell Banshee"),
    (r"Berserker", "a Fell Berserker"),
    (r"Cyclops_Fog|Cyclops_Fo(g)?ger", "a Fell Cyclops"),
    (r"Fog(ger)?_Heavy|Heavy_Fogger", "a Fell Brute"),
    (r"MageHeavy|Fogger_Mage", "a Fell Mage"),
    (r"SporeHead|ShroudSeeker", "a Fell Spore Mage"),
    (r"Ranger_Elite_Sentinel", "a Fell Sentinel"),
    (r"Fog(ger)?_Ranger", "a Fell Archer"),
    (r"Fog(ger)?_Sol(d)?ier", "a Fell Soldier"),
    (r"Depleted", "a Fell Thrall"),
    (r"Blossom|Spitter", "a Fell Spitter"),
    (r"Ranger_FogGrenade", "a Fell Archer"),
    (r"Critter_Hover", "an exploding Critter"),
    (r"FogCrab", "a Fell Crab"),
    (r"Jelly", "a Fell Jellyfish"),
    (r"FogNestDrone", "a Fell Nest Drone"),
    (r"InfestedBoar", "an Infested Boar"),
    (r"Tentacle", "a Fell Tentacle"),
    (r"Fog_Slime", "a Fell Slime"),
    (r"Fog_Mushroom|Giant_Mushroom", "a Fell Mushroom"),
    (r"Fog(_Bug)?_Critter|Bug_Critter_Suicider", "an exploding Critter"),
    (r"Bug_Critter", "a Critter"),
    (r"Fogger|Enemy_Fog_", "a Fell"),
    # The Hollow
    (r"Necromancer", "a Hollow Necromancer"),
    (r"FlyingSkull", "a Flying Skull"),
    (r"(Skeleton|Hollow).*Cyclops|Skeleton_Heavy", "a Hollow Cyclops"),
    (r"Skeleton.*Mage", "a Hollow Mage"),
    (r"Skeleton.*Hound", "a Hollow Hound"),
    (r"Skeleton.*Weakling", "a Hollow Weakling"),
    (r"Skeleton_Elite", "a Hollow Elite"),
    (r"HollowWisp", "a Hollow Wisp"),
    (r"Skeleton", "a Hollow Warrior"),
    # Scavengers
    (r"Tyrant", "a Scavenger Tyrant"),
    (r"Heavy_?Mage_Hound|HeavyMage_Hounds", "a Scavenger Matron"),
    (r"Heavy_?Mage|Scavenger.*Acid", "a Scavenger Acid Mage"),
    (r"Scavenger.*SnowSabertooth", "a tamed Snow Sabertooth"),
    (r"Scavenger.*Hound|Hound_Pet", "a Scavenger Hound"),
    (r"Scavenger.*Cannon|Scavenger.*Barrage", "a Scavenger Cannoneer"),
    (r"Scavenger.*(Crossbow|Repeater)", "a Scavenger Crossbowman"),
    (r"Scavenger.*Flamethrower|Firelance", "a Scavenger Flamethrower"),
    (r"Scavenger.*FireElite", "a Scavenger Fire Elite"),
    (r"Scavenger.*(Heavy_Club|Bully)", "a Scavenger Brute"),
    (r"Scavenger.*EliteArmored", "an Armored Scavenger"),
    (r"Scavenger.*Weakling", "a Scavenger Weakling"),
    (r"Scavenger.*Ranger", "a Scavenger Archer"),
    (r"Scavenger", "a Scavenger"),
    # Vukah
    (r"Vukah.*(Shaman|Heal)", "a Vukah Shaman"),
    (r"Vukah.*Armored", "an Armored Vukah"),
    (r"Vukah", "a Vukah"),
    # Beasts
    (r"Wolf_Heavy", "an Alpha Wolf"),
    (r"Wolf", "a Wolf"),
    (r"SnowSabertooth", "a Snow Sabertooth"),
    (r"Sabertooth", "a Sabertooth"),
    (r"Boar", "a Boar"),
    (r"Croc", "a Crocodile"),
    (r"GiantCrab|Crab_WaterSnap", "a Giant Crab"),
    (r"Scorpion_Fire", "a Fire Scorpion"),
    (r"Scorpion", "a Scorpion"),
    (r"SpiderAnt_Huge", "a Giant Spider"),
    (r"SpiderAnt.*Poison", "a Poison Spider"),
    (r"SpiderAnt|Plant_Spider", "a Spider"),
    (r"Bat_Frost", "a Frost Bat"),
    (r"Bat_Shock", "a Shock Bat"),
    (r"_Bat_", "a Bat"),
    (r"_Rat_", "a Rat"),
    (r"Raven", "a Raven"),
    (r"Vulture", "a Vulture"),
    (r"Sand_?digger|Stonedigger", "a Sand Digger"),
    (r"Stinger", "a Stinger"),
    (r"Mosquito", "a Mosquito Swarm"),
    (r"Wasp", "a Wasp Swarm"),
    (r"Will_?o_?Wisp_Explosive", "an Explosive Wisp"),
    (r"Will_?o_?Wisp", "a Will-o'-Wisp"),
    (r"IceWisp", "an Ice Wisp"),
    (r"FireWisp", "a Fire Wisp"),
    (r"Cyclops", "a Cyclops"),
    (r"Mushroom", "a Mushroom"),
    (r"Tornado", "a Tornado"),
    (r"Yak", "a Yak"),
    (r"Goat", "a Goat"),
    # Traps and props
    (r"Sawblade", "a saw blade trap"),
    (r"Pendulum", "a pendulum trap"),
    (r"Spike|Spikey|Pil(l)?ar", "a spike trap"),
    (r"Magmaball|Magma", "a magma trap"),
    (r"Bamboo|blowpipe", "a dart trap"),
    (r"FallTrap", "a falling trap"),
    (r"Beam", "a beam trap"),
    (r"^Trap_|_Trap_", "a trap"),
    (r"barrel", "an exploding barrel"),
]
_RULES = [(re.compile(p, re.I), name) for p, name in RULES]

# Only templates that can deal damage get a name (props, labels, loot... never kill).
_DAMAGING = re.compile(r"^(Enemy|Animal|Projectile|Explosion|Attack|Trap|Player|Hitable)_|explosi", re.I)


def readable(internal):
    if not _DAMAGING.search(internal):
        return None
    for rx, name in _RULES:
        if rx.search(internal):
            return name
    return None


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    out_path = argv[2] if len(argv) > 2 else "killers.json"
    templates = read_templates(argv[1].rstrip("/\\") + "/enshrouded_server")
    table = {g: n for g, n in ((g, readable(i)) for g, i in templates.items()) if n}
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(dict(sorted(table.items())), f, indent=0)
        f.write("\n")
    print(f"{len(templates)} templates, {len(table)} named -> {out_path}")


if __name__ == "__main__":
    main(sys.argv)
