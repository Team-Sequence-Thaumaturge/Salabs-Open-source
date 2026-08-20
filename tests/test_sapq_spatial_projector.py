import unittest
import os
from modules.sapq.sapq_spatial_projector import SpatialProjector

class TestSAPQSpatialProjector(unittest.TestCase):
    def setUp(self):
        # Create a dummy JS file to parse
        self.test_filepath = "dummy_spatial_test.js"
        with open(self.test_filepath, "w", encoding="utf-8") as f:
            f.write("""
            function init() {
                const a = 1;
                document.getElementById('btn');
            }
            init();
            setTimeout(() => {
                console.log('async');
            }, 100);
            function Math_random_mock() {
                // we'll explicitly not use Math.random() in projector
            }
            """)

    def tearDown(self):
        if os.path.exists(self.test_filepath):
            os.remove(self.test_filepath)
        # Also clean up SAPQ checkpoint if any
        ckpt = f".sapq_logs/checkpoint_{os.path.basename(self.test_filepath)}.json"
        if os.path.exists(ckpt):
            os.remove(ckpt)

    def test_tensor_format(self):
        projector = SpatialProjector(self.test_filepath)
        tensors = projector.generate_tensors()

        self.assertIn("count", tensors)
        self.assertIn("positions", tensors)
        self.assertIn("colors", tensors)
        self.assertIn("torsionTensors", tensors)
        self.assertIn("reconciliationVectors", tensors)
        self.assertIn("gravitySinks", tensors)

        self.assertTrue(isinstance(tensors["count"], int))
        self.assertTrue(isinstance(tensors["positions"], list))
        self.assertTrue(isinstance(tensors["colors"], list))
        self.assertTrue(isinstance(tensors["torsionTensors"], list))
        self.assertTrue(isinstance(tensors["reconciliationVectors"], list))
        self.assertTrue(isinstance(tensors["gravitySinks"], list))

        # Check matching array sizes according to Three.js InstancedMesh flattening expectations
        count = tensors["count"]
        self.assertEqual(len(tensors["positions"]), count * 3)
        self.assertEqual(len(tensors["colors"]), count * 3)
        self.assertEqual(len(tensors["torsionTensors"]), count * 3)
        self.assertEqual(len(tensors["reconciliationVectors"]), count * 3)
        self.assertEqual(len(tensors["gravitySinks"]), count * 4) # x, y, z, depth

    def test_deterministic_math(self):
        projector1 = SpatialProjector(self.test_filepath)
        tensors1 = projector1.generate_tensors()

        projector2 = SpatialProjector(self.test_filepath)
        tensors2 = projector2.generate_tensors()

        # Test exact equality to verify NO Math.random() is used
        self.assertEqual(tensors1["positions"], tensors2["positions"])
        self.assertEqual(tensors1["colors"], tensors2["colors"])
        self.assertEqual(tensors1["torsionTensors"], tensors2["torsionTensors"])
        self.assertEqual(tensors1["reconciliationVectors"], tensors2["reconciliationVectors"])
        self.assertEqual(tensors1["gravitySinks"], tensors2["gravitySinks"])

        # Parse the file itself to make sure Math.random() isn't literally written anywhere (except comments/docstrings)
        with open("modules/sapq/sapq_spatial_projector.py", "r", encoding="utf-8") as f:
            code_lines = f.readlines()
            for line in code_lines:
                if not line.strip().startswith("#") and '"""' not in line:
                    self.assertNotIn("Math.random()", line)
                    self.assertNotIn("random.", line)

if __name__ == '__main__':
    unittest.main()
