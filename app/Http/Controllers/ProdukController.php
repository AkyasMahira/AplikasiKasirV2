<?php

namespace App\Http\Controllers;

use App\Models\LogStok;
use App\Models\Produk;
use Barryvdh\DomPDF\Facade\Pdf;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Milon\Barcode\Facades\DNS1DFacade;

class ProdukController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $title = 'Produk';
        $subtitle = 'Index';
        $produkBaru = Produk::where('created_at', '>=', Carbon::now()->subMinute())->exists();
        $produks = Produk::all();

        return view('admin.produk.index',  compact('title', 'subtitle',  'produks'));
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        $title = 'Produk';
        $subtitle = 'Create';
        return view('admin.produk.create', compact('title', 'subtitle'));
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        $validate = $request->validate([
            'NamaProduk' => 'required',
            'Harga' => 'required|numeric',
            'Stok' => 'required|numeric',
        ]);
        $validate['Users_id'] = Auth::user()->id;
        $simpan = Produk::create($validate);
        if ($simpan) {
            return response()->json(['status' => 200, 'message' => 'Data Produk Baru Berhasil Ditambahkan.']);
        } else {
            return response()->json(['status' => 422, 'message' => 'Data Produk Baru Gagal Ditambahkan.']);
        }
    }

    /**
     * Display the specified resource.
     */
    public function show(Produk $produk)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit($id)
    {
        $judulHalaman = 'Edit Produk | POSMate';
        $title = 'Produk';
        $subtitle = 'Edit';
        $produk = Produk::find($id);
        return view('admin.produk.edit', compact('title', 'subtitle', 'produk', 'judulHalaman'));
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, Produk $produk)
    {
        $validate = $request->validate([
            'NamaProduk' => 'required',
            'Harga' => 'required|numeric',
            'Stok' => 'required|numeric',
        ]);
        $validate['Users_id'] = Auth::user()->id;
        $simpan = $produk->update($validate);
        if ($simpan) {
            return response()->json(['status' => 200, 'message' => 'Data Produk Berhasil Diubah.']);
        } else {
            return response()->json(['status' => 422, 'message' => 'Data Produk Gagal Diubah.']);
        }
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy($id)
    {
        // Cari produk berdasarkan ID
        $produk = Produk::find($id);

        // Jika produk tidak ditemukan, kembalikan dengan pesan error
        if (!$produk) {
            return redirect(route('produk.index'))->with('error', 'Produk tidak ditemukan.');
        }

        // Coba hapus produk
        if ($produk->delete()) {
            return redirect(route('produk.index'))->with('success', 'Data Produk berhasil dihapus.');
        } else {
            // Jika penghapusan gagal karena alasan lain
            return redirect(route('produk.index'))->with('error', 'Data Produk gagal dihapus.');
        }
    }
    // public function destroy($id)
    // {
    //     $produk = Produk::find($id);
    //     $delete = $produk->delete();
    //     if ($delete) {
    //         return redirect(route('produk.index'))->with('success', 'Data Produk Berhasil Dihapus.');
    //     } else {
    //         return redirect(route('produk.index'))->with('success', 'Data Produk Gagal Dihapus.');
    //     }
    // }

    public function tambahStok(Request $request, $id)
    {
        // Validasi input
        $validate = $request->validate([
            'Stok' => 'required|numeric',
        ]);

        // Cari produk berdasarkan ID
        $produk = Produk::find($id);

        // Jika produk tidak ditemukan, kembalikan respons 404
        if (!$produk) {
            return response()->json([
                'status' => 404,
                'message' => 'Produk Tidak Ditemukan!'
            ], 404);
        }

        // Tambahkan stok dan simpan perubahan
        $produk->Stok += $validate['Stok'];
        if ($produk->save()) {
            return response()->json([
                'status' => 200,
                'message' => 'Stok Berhasil Ditambahkan!'
            ], 200);
        } else {
            // Jika penyimpanan gagal
            return response()->json([
                'status' => 500,
                'message' => 'Stok Gagal Ditambahkan!'
            ], 500);
        }
    }
    // public function tambahStok(Request $request, $id)
    // {
    //     $validate = $request->validate([
    //         'Stok' => 'required|numeric',
    //     ]);
    //     $produk = Produk::find($id);
    //     $produk->Stok += $validate['Stok'];
    //     $update = $produk->save();
    //     if($update){
    //         return response()->json()(['status', => 200, 'message', => 'Stok Berhasil Ditambahkan!']);
    //     } else {
    //         return response()->json()(['status', => 500, 'message', => 'Stok Gagal Ditambahkan!']);

    //     }
    // }
    public function logproduk()
    {
        $title = 'Produk';
        $subtitle = 'Log Produk';
        $produks = LogStok::join('produks', 'log_stoks.ProdukId', '=', 'produks.id')
        ->join('users', 'log_stoks.UsersId', '=', 'users.id')
        ->select('log_stoks.JumlahProduk', 'log_stoks.created_at', 'produks.NamaProduk', 'users.name')->get();
        return view('admin.produk.logproduk', compact('title', 'subtitle', 'produks'));

    }

    public function cetakLabel(Request $request)
    {
        $id_produk = $request->id_produk;
        $barcodes = [];

        if (is_array($id_produk)) {
            foreach ($id_produk as $id) {
                $id = (string) $id;
                $harga = Produk::find($id)->Harga;
                $barcode = DNS1DFacade::getBarcodeHTML($id, 'C128');
                $barcodes[] = ['barcode' => $barcode, 'harga' => $harga];
            }
        } else {
            $id_produk = (string) $id_produk;
            $harga = Produk::find($id_produk)->Harga;
            $barcode = DNS1DFacade::getBarcodeHTML($id_produk, 'C128');
            $barcodes[] = ['barcode' => $barcode, 'harga' => $harga];
        }
        $pdf = Pdf::loadView('admin.produk.cetaklabel', compact('barcodes'));

        $file_path = storage_path('app/public/barcodes.pdf');
        $pdf->save($file_path);

        return response()->json(['url' => asset('storage/barcodes.pdf')]);
    }
}
