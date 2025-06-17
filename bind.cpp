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
}