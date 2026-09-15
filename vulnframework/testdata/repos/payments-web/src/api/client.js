import axios from "axios";

export async function fetchInvoice(id) {
  const response = await axios.get(`/api/invoices/${id}`);
  console.log("response", response);
  return response.data;
}
