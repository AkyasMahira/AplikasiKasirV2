<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class DetailPenjualan extends Model
{
    protected $fillable = ['PenjualanId', 'ProdukId', 'harga', 'JumlahProduk', 'SubTotal'];
}
