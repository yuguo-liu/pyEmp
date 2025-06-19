#include <pybind11/pybind11.h>
#include "pyEmp.h"

namespace py = pybind11;

PYBIND11_MODULE(pyEmp, m) {
     py::class_<EmpAg2pcGarbledCircuit>(m, "EmpAg2pcGarbledCircuit")
          .def(py::init<std::string, int, const char*, int, bool>(),
               py::arg("circuit_file_name"),
               py::arg("party"),
               py::arg("IP"),
               py::arg("port"),
               py::arg("debug") = false)
          .def("offline_computation", &EmpAg2pcGarbledCircuit::offline_computation)
          .def("online_computation", &EmpAg2pcGarbledCircuit::online_computation,
               py::arg("hin") = "", py::arg("check_output") = "");
     py::class_<EmpECtF>(m, "EmpECtF")
          .def(py::init<int, const char*, int, bool, bool>(),
               py::arg("party"),
               py::arg("IP"),
               py::arg("port"),
               py::arg("debug") = false,
               py::arg("log") = false)
          .def("offline_computation", &EmpECtF::offline_computation)
          .def("online_computation", &EmpECtF::online_computation,
               py::arg("hin") = "", py::arg("check_output") = "");
     py::class_<EmpTlsPrf384>(m, "EmpTlsPrf384")
          .def(py::init<int, const char*, int, bool>(),
               py::arg("party"),
               py::arg("IP"),
               py::arg("port"),
               py::arg("debug") = false)
          .def("offline_computation", &EmpTlsPrf384::offline_computation)
          .def("online_computation", &EmpTlsPrf384::online_computation,
               py::arg("rnd_s"),
               py::arg("rnd_c"),
               py::arg("share"),
               py::arg("check_output") = "");
     py::class_<EmpTlsPrf320>(m, "EmpTlsPrf320")
          .def(py::init<int, const char*, int, bool>(),
               py::arg("party"),
               py::arg("IP"),
               py::arg("port"),
               py::arg("debug") = false)
          .def("offline_computation", &EmpTlsPrf320::offline_computation)
          .def("online_computation", &EmpTlsPrf320::online_computation,
               py::arg("rnd_s"),
               py::arg("rnd_c"),
               py::arg("share"),
               py::arg("check_output") = "");
     py::class_<EmpTlsPrfCFSF>(m, "EmpTlsPrfCFSF")
          .def(py::init<int, const char*, int, string, bool>(),
               py::arg("party"),
               py::arg("IP"),
               py::arg("port"),
               py::arg("msg"),
               py::arg("debug") = false)
          .def("offline_computation", &EmpTlsPrfCFSF::offline_computation)
          .def("online_computation", &EmpTlsPrfCFSF::online_computation,
               py::arg("seed"),
               py::arg("share"),
               py::arg("check_output") = "");
     py::class_<EmpNaiveAesGcmEnc>(m, "EmpNaiveAesGcmEnc")
          .def(py::init<int, const char*, int, int, int, bool>(),
               py::arg("party"),
               py::arg("IP"),
               py::arg("port"),
               py::arg("len_c"),
               py::arg("len_a"),
               py::arg("debug") = false)
          .def("offline_computation", &EmpNaiveAesGcmEnc::offline_computation)
          .def("online_computation", &EmpNaiveAesGcmEnc::online_computation,
               py::arg("m"),
               py::arg("ad"),
               py::arg("key_share"),
               py::arg("iv_share"));
}