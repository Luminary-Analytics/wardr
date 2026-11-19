"""Render Wardr's original shield asset with Blender in background mode."""

from pathlib import Path

import bpy
from mathutils import Matrix, Vector


ROOT = Path(__file__).resolve().parents[1]
bpy.ops.object.select_all(action="SELECT")
bpy.ops.object.delete(use_global=False)


def material(name, color, metallic, roughness, emission=0.0):
    item = bpy.data.materials.new(name)
    if item.node_tree is None:
        item.use_nodes = True
    shader = item.node_tree.nodes.get("Principled BSDF")
    shader.inputs["Base Color"].default_value = (*color, 1)
    shader.inputs["Metallic"].default_value = metallic
    shader.inputs["Roughness"].default_value = roughness
    shader.inputs["Emission Color"].default_value = (*color, 1)
    shader.inputs["Emission Strength"].default_value = emission
    return item


def solid(name, outline, lower, upper, surface, bevel):
    length = len(outline)
    points = [(x, y, z) for z in (lower, upper) for x, y in outline]
    faces = [tuple(reversed(range(length))), tuple(range(length, length * 2))]
    for index in range(length):
        following = (index + 1) % length
        faces.append((index, following, length + following, length + index))
    mesh = bpy.data.meshes.new(name)
    mesh.from_pydata(points, [], faces)
    mesh.update()
    item = bpy.data.objects.new(name, mesh)
    bpy.context.collection.objects.link(item)
    item.data.materials.append(surface)
    modifier = item.modifiers.new("Machined edges", "BEVEL")
    modifier.width = bevel
    modifier.segments = 4
    item.modifiers.new("Weighted normals", "WEIGHTED_NORMAL")
    return item


def scale(outline, amount):
    return [(x * amount, y * amount) for x, y in outline]


def light(name, location, power, color, size):
    data = bpy.data.lights.new(name, "AREA")
    data.energy = power
    data.color = color
    data.shape = "DISK"
    data.size = size
    lamp = bpy.data.objects.new(name, data)
    bpy.context.collection.objects.link(lamp)
    lamp.location = location
    lamp.rotation_euler = (-lamp.location).to_track_quat("-Z", "Y").to_euler()


shield = [
    (0, 1.44), (-1.12, 1.03), (-1.10, -0.05), (-0.85, -0.64),
    (-0.43, -1.08), (0, -1.38), (0.43, -1.08), (0.85, -0.64),
    (1.10, -0.05), (1.12, 1.03),
]
check = [
    (-0.53, 0.11), (-0.18, -0.22), (0.48, 0.45), (0.65, 0.29),
    (-0.18, -0.56), (-0.70, -0.05),
]
metal = material("Graphite titanium", (0.024, 0.067, 0.077), 0.77, 0.29)
rim = material("Mint anodized metal", (0.10, 0.82, 0.55), 0.51, 0.29, 0.25)
inset = material("Deep green ceramic", (0.014, 0.052, 0.054), 0.48, 0.30)
mint = material("Mint enamel", (0.15, 0.93, 0.69), 0.36, 0.27, 0.5)

solid("Shield body", shield, -0.22, 0.12, metal, 0.08)
solid("Shield rim", scale(shield, 0.933), 0.09, 0.166, rim, 0.029)
solid("Inset panel", scale(shield, 0.857), 0.15, 0.205, inset, 0.041)
solid("Checkmark", list(reversed(check)), 0.20, 0.30, mint, 0.037)

light("Key", (-3, 4, 4), 650, (0.70, 1, 0.90), 4)
light("Fill", (4, 1, 2), 430, (0.30, 0.72, 1), 3)
light("Edge", (0, -4, 2), 220, (0.50, 1, 0.75), 3)

scene = bpy.context.scene
bpy.ops.object.camera_add(location=(2.2, 1.15, 9.5))
scene.camera = bpy.context.object
back = scene.camera.location.normalized()
right = Vector((0, 1, 0)).cross(back).normalized()
up = back.cross(right)
scene.camera.rotation_euler = Matrix((right, up, back)).transposed().to_euler()
scene.camera.data.type = "ORTHO"
scene.camera.data.ortho_scale = 3.18
scene.render.engine = "CYCLES"
scene.cycles.samples = 24
scene.cycles.use_denoising = True
scene.render.resolution_x = scene.render.resolution_y = 320
scene.render.resolution_percentage = 100
scene.render.film_transparent = True
scene.render.image_settings.color_mode = "RGBA"
scene.render.filepath = "//../wardr/static/wardr-mark.png"
scene.name = "Wardr dashboard shield"

model = ROOT / "design" / "wardr-triposr.glb"
if model.is_file():
    existing = set(bpy.data.objects)
    bpy.ops.import_scene.gltf(filepath=str(model))
    reference = bpy.data.scenes.new("TripoSR reconstruction")
    for item in set(bpy.data.objects) - existing:
        for collection in list(item.users_collection):
            collection.objects.unlink(item)
        reference.collection.objects.link(item)

bpy.ops.object.select_all(action="DESELECT")
scene.camera.select_set(True)
bpy.context.view_layer.objects.active = scene.camera
bpy.context.preferences.filepaths.save_version = 0
bpy.ops.wm.save_as_mainfile(filepath=str(ROOT / "design" / "wardr-mark.blend"))
bpy.ops.render.render(write_still=True)
